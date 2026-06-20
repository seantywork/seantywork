#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/dmaengine.h>
#include <linux/dma-mapping.h>
#include <linux/types.h>
#include <linux/kdev_t.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/platform_device.h>
#include <linux/mod_devicetable.h>
#include <linux/device.h>
#include <linux/device/driver.h>
#include <linux/interrupt.h>


#define SYSFS_DUMMY_DEV "dmadummy"
#define SYSFS_DUMMY_FILE dmadummy_file
#define IRQ_1		1
#define DUMMY_DEV_NAME    "kirq_key"
#define DUMMY_DEV_ID    	"0001"

static struct platform_device *dma_dummy_pdev = NULL;
static int dma_dummy_file_stat = -1;
static int irq_registered = 0;

static struct of_device_id dma_dummy_of_match[] ={
    { .compatible = SYSFS_DUMMY_DEV },
    {}
};
static struct device_driver dma_dummy_driver = {
    .name = SYSFS_DUMMY_DEV,
    .owner = THIS_MODULE,
    .of_match_table = dma_dummy_of_match,
};

static struct dma_device* dma_dummy_ddev = NULL;
static struct dma_chan* dma_dummy_chan = NULL;
static struct dma_async_tx_descriptor* dma_dummy_async_tx = NULL;
static int dma_registered = 0;
static char dma_dummy_chan_name[64] = {0};

static void *src = NULL;
static void *dst = NULL;
static struct dma_chan *kdma_ch = NULL;

unsigned char dma_align;
unsigned int dma_align_len;

static int kdma_transfer(const void *kdma_src, void *kdma_dst, unsigned int len){

	enum dma_status status = DMA_ERROR;
	struct dmaengine_unmap_data *kdma_unmap_data;
	struct page *_page;
	unsigned long _page_off;
	struct dma_device *_dev;
	struct dma_async_tx_descriptor *_tx = NULL;
	dma_addr_t _dma_srcaddr, _dma_dstaddr;
	dma_cookie_t _dma_cookie;
	dma_cap_mask_t mask;
	dma_cap_zero(mask);
	dma_cap_set(DMA_MEMCPY, mask);	

	dma_align = 0;
	dma_align_len = len;

	dma_align_len = (dma_align_len >> dma_align) << dma_align;
	if (dma_align_len == 0) {
			dma_align_len = 1 << dma_align;
	}
	printk(KERN_INFO "kdma transfer: before dst: %d, src: %d, len: %u", *(int *)dst, *(int *)src, dma_align_len);
		
	/*
	kdma_ch = dma_request_chan(&dma_dummy_pdev->dev, dma_dummy_chan_name);
	if(IS_ERR(kdma_ch)){
		kdma_ch = NULL;
		printk(KERN_INFO "kdma transfer: failed to request dma chan\n");
		return -1;
	}*/
	kdma_ch = dma_dummy_chan;
	_dev = kdma_ch->device;

	kdma_unmap_data = dmaengine_get_unmap_data(_dev->dev, 2, GFP_KERNEL);
	if(kdma_unmap_data == NULL){
		printk(KERN_INFO "kdma transfer: failed to get unmap data\n");
		return -1;
	}
	kdma_unmap_data->len = dma_align_len;
	_page = virt_to_page(kdma_src);
	if(_page == NULL){
		printk(KERN_INFO "kdma transfer: failed to get page: 0\n");
		return -1;
	}
	_page_off = offset_in_page(kdma_src);
	kdma_unmap_data->addr[0] = dma_map_page(_dev->dev, _page, _page_off, dma_align_len, DMA_TO_DEVICE);
	if(dma_mapping_error(_dev->dev, kdma_unmap_data->addr[0])){
		printk(KERN_INFO "kdma transfer: mappping error for src\n");
		return -1;
	}
	kdma_unmap_data->to_cnt = 1;
	_dma_srcaddr = kdma_unmap_data->addr[0];


	_page = virt_to_page(kdma_dst);
	if(_page == NULL){
		printk(KERN_INFO "kdma transfer: failed to get page: 1\n");
		return -1;
	}
	_page_off = offset_in_page(kdma_dst);
	kdma_unmap_data->addr[1] = dma_map_page(_dev->dev, _page, _page_off, dma_align_len, DMA_FROM_DEVICE);
	if(dma_mapping_error(_dev->dev, kdma_unmap_data->addr[1])){
		printk(KERN_INFO "kdma transfer: mappping error for dst\n");
		return -1;
	}
	kdma_unmap_data->from_cnt = 1;
	_dma_dstaddr = kdma_unmap_data->addr[1];

	_tx = _dev->device_prep_dma_memcpy(kdma_ch, _dma_dstaddr, _dma_srcaddr, dma_align_len, DMA_CTRL_ACK);
	if(_tx == NULL){
		printk(KERN_INFO "kdma transfer: tx prep error\n");
		return -1;
	}
	_dma_cookie = _tx->tx_submit(_tx);
	if(dma_submit_error(_dma_cookie)){
		printk(KERN_INFO "kdma transfer: cookie error\n");
		return -1;
	}

	dma_async_issue_pending(kdma_ch);
	for(;;){
		status = dma_async_is_tx_complete(kdma_ch, _dma_cookie, NULL, NULL); 
		if (status != DMA_COMPLETE) {
			switch (status) {
				case DMA_IN_PROGRESS:
					printk(KERN_INFO "kdma transfer: DMA in progres, hit Ctrl+c to complete...");
					break;
				case DMA_PAUSED:
					printk(KERN_INFO "kdma transfer: DMA paused...");
					break;
				case DMA_ERROR:
					printk(KERN_INFO "kdma transfer: DMA error");
					break;
				default:
					;
				}
		} else {
			printk(KERN_INFO "kdma transfer: DMA transfer complete...");
			break;
		}
	}

	printk(KERN_INFO "kdma transfer: after dst: %d, src: %d", *(int *)dst, *(int *)src);
	dmaengine_unmap_put(kdma_unmap_data);
	dmaengine_terminate_sync(kdma_ch);
	dma_release_channel(kdma_ch);
	return 0;
}

static ssize_t dmadummy_file_show(struct device *dev, struct device_attribute *attr, char *buf){
	int n = 0;
	return n;
}

static ssize_t dmadummy_file_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count){
	int ret = 0;
	return ret;
}

static DEVICE_ATTR_RW(SYSFS_DUMMY_FILE);

static inline void dma_cookie_init(struct dma_chan *chan)
{
	chan->cookie = DMA_MIN_COOKIE;
	chan->completed_cookie = DMA_MIN_COOKIE;
}

static inline enum dma_status dma_cookie_status(struct dma_chan *chan,
	dma_cookie_t cookie, struct dma_tx_state *state)
{
	dma_cookie_t used, complete;

	used = chan->cookie;
	complete = chan->completed_cookie;
	barrier();
	if (state) {
		state->last = complete;
		state->used = used;
		state->residue = 0;
		state->in_flight_bytes = 0;
	}
	return dma_async_is_complete(cookie, complete, used);
}

static inline dma_cookie_t dma_cookie_assign(struct dma_async_tx_descriptor *tx)
{
	struct dma_chan *chan = tx->chan;
	dma_cookie_t cookie;

	cookie = chan->cookie + 1;
	if (cookie < DMA_MIN_COOKIE)
		cookie = DMA_MIN_COOKIE;
	tx->cookie = chan->cookie = cookie;

	return cookie;
}

static dma_cookie_t _tx_submit(struct dma_async_tx_descriptor *tx){
	dma_cookie_t cookie;
	cookie = dma_cookie_assign(tx);
	return cookie;
}

static void _issue_pending(struct dma_chan *chan){

	/*
	 * update the engine with the number of descriptors to
	 * process
	 */

}

static struct dma_async_tx_descriptor *_prep_dma_memcpy(struct dma_chan *chan, dma_addr_t dest, dma_addr_t src, size_t len, unsigned long flags){
	return dma_dummy_async_tx;
}

static void _device_destroy(void){
	if(dma_dummy_async_tx != NULL){
		kfree(dma_dummy_async_tx);
	}
	if(dma_dummy_chan != NULL){
		kfree(dma_dummy_chan);
	}
	if(dma_dummy_ddev != NULL){
		if(dma_registered){
			dma_async_device_unregister(dma_dummy_ddev);
		}
		kfree(dma_dummy_ddev);
	}
	if(dma_dummy_pdev != NULL){
		if(dma_dummy_file_stat != -1){
			device_remove_file(&dma_dummy_pdev->dev, &dev_attr_SYSFS_DUMMY_FILE);
		}
		if(!dma_registered){
			platform_device_unregister(dma_dummy_pdev);	
		}
		//platform_device_unregister(dma_dummy_pdev);
	}
	if(irq_registered){
		free_irq(IRQ_1, DUMMY_DEV_ID);
	}

}

static irq_handler_t irq_1_handler(unsigned int irq, void* dev_id, struct pt_regs *regs){
	printk("Device ID %s; Keyboard interrupt occured\n", (char*)dev_id);
	memcpy(dst, src, dma_align_len);

	dma_dummy_chan->completed_cookie = dma_dummy_chan->cookie;
    return (irq_handler_t)IRQ_HANDLED;
}


static int _device_create(void){
	int result = -1;
	dma_dummy_pdev = platform_device_register_simple(SYSFS_DUMMY_DEV, -1, NULL, 0);
	if(IS_ERR(dma_dummy_pdev)){
		dma_dummy_pdev = NULL;
		printk(KERN_INFO "failed to register platdev\n");
		goto error;
	}
	dma_dummy_pdev->dev.driver = &dma_dummy_driver;
	dma_dummy_file_stat = device_create_file(&dma_dummy_pdev->dev, &dev_attr_SYSFS_DUMMY_FILE);
	if(dma_dummy_file_stat){
		dma_dummy_file_stat = -1;
		printk(KERN_INFO "failed to create device file\n");
		goto error;
	}
	result = dma_set_mask_and_coherent(&dma_dummy_pdev->dev, DMA_BIT_MASK(40));
	if(result){
		printk(KERN_INFO "failed to set dma mask\n");
		goto error;
	}
	printk(KERN_INFO "device created\n");
	dma_dummy_ddev = kzalloc(sizeof(struct dma_device), GFP_KERNEL);
	dma_dummy_chan = kzalloc(sizeof(struct dma_chan), GFP_KERNEL);
	dma_dummy_async_tx = kzalloc(sizeof(struct dma_async_tx_descriptor), GFP_KERNEL);
	printk(KERN_INFO "dma dev allocated\n");
	dma_async_tx_descriptor_init(dma_dummy_async_tx, dma_dummy_chan);
	printk(KERN_INFO "dma tx descriptor init\n");
	dma_dummy_async_tx->tx_submit = _tx_submit;
	async_tx_ack(dma_dummy_async_tx);
	printk(KERN_INFO "dma tx descriptor ack\n");
	dma_cookie_init(dma_dummy_chan);
	printk(KERN_INFO "dma cookie init done\n");
	dma_cap_zero(dma_dummy_ddev->cap_mask);
	dma_cap_set(DMA_MEMCPY, dma_dummy_ddev->cap_mask);
	INIT_LIST_HEAD(&dma_dummy_ddev->channels);
	printk(KERN_INFO "dma dev set done\n");
	dma_dummy_ddev->device_tx_status = dma_cookie_status;
	dma_dummy_ddev->device_issue_pending = _issue_pending;
	dma_dummy_ddev->dev = &dma_dummy_pdev->dev;

	printk(KERN_INFO "dma dev linked\n");
	
	dma_dummy_ddev->device_prep_dma_memcpy = _prep_dma_memcpy;

	dma_dummy_chan->device = dma_dummy_ddev;

	list_add_tail(&dma_dummy_chan->device_node, &dma_dummy_ddev->channels);
	printk(KERN_INFO "dma channnel linked\n");
	result = dma_async_device_register(dma_dummy_ddev);
	if(result){
		printk(KERN_INFO "failed to register dma async device\n");
		goto error;
	}
	dma_registered = 1;
	strcpy(dma_dummy_chan_name, dma_chan_name(dma_dummy_chan));
	printk(KERN_INFO "dma device registered: %s\n", dma_dummy_chan_name);
    if (request_irq(IRQ_1, (irq_handler_t)irq_1_handler, IRQF_SHARED, DUMMY_DEV_NAME, DUMMY_DEV_ID) != 0){
        printk("can't request interrupt number %d\n", IRQ_1);
		goto error;
    } else {
		printk("requested interrupt number %d successfully\n", IRQ_1);
	}
	irq_registered = 1;
	return 0;
error:
	_device_destroy();
	return -1;
}

static int __init mod_init(void)
{
	int *writer;
	printk(KERN_INFO "kdma: in init\n");
	if(_device_create() < 0){
		printk(KERN_INFO "failed to init dev\n");
		return -1;
	}
	src = kzalloc(16,GFP_KERNEL);
	dst = kzalloc(16,GFP_KERNEL);
	writer = (int *)src;
	*writer = 65;
	printk(KERN_INFO "kdma mod_init: before dst: %d, src: %d", *(int *)dst, *(int *)src);
	if(kdma_transfer(src, dst, 16) < 0){
		kfree(src);
		kfree(dst);
		_device_destroy();
		printk(KERN_INFO "kdma mod_init: failed to init\n");
		return -1;
	}
	printk(KERN_INFO "kdma mod_init: after dst: %d, src: %d", *(int *)dst, *(int *)src);
	printk(KERN_INFO "kdma mod_init: init done\n");

	return 0;
}

static void __exit mod_exit(void)
{
    printk(KERN_INFO "kdma mod_exit: mod_exit called\n");
	if(src != NULL){
		kfree(src);
	}
	if(dst != NULL){
		kfree(dst);
	}
	_device_destroy();
    printk(KERN_INFO "kdma mod_exit: done\n");
}

module_init(mod_init);
module_exit(mod_exit);

MODULE_AUTHOR("seantywork");
MODULE_LICENSE("GPL");
