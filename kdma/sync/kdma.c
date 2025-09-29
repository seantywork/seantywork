#include <linux/module.h>
#include <linux/init.h>
#include <linux/dmaengine.h>
#include <linux/dma-mapping.h>

void *src,  *dst;
struct dma_chan *kdma_ch;

static int kdma_transfer(const void *kdma_src, void *kdma_dst, unsigned int len){

	enum dma_status status = DMA_ERROR;
	struct dmaengine_unmap_data *kdma_unmap_data;
	unsigned char align;
	unsigned int align_len;
	struct page *_page;
	unsigned long _page_off;
	struct dma_device *_dev;
	struct dma_async_tx_descriptor *_tx = NULL;
	dma_addr_t _dma_srcaddr, _dma_dstaddr;
	dma_cookie_t _dma_cookie;
	dma_cap_mask_t mask;
	dma_cap_zero(mask);
	dma_cap_set(DMA_MEMCPY, mask);	

	align = 0;
	align_len = len;

	align_len = (align_len >> align) << align;
	if (align_len == 0) {
			align_len = 1 << align;
	}
	printk(KERN_INFO "kdma transfer: before dst: %d, src: %d, len: %u", *(int *)dst, *(int *)src, align_len);
		
	kdma_ch = dma_request_channel(mask, NULL, NULL);
	if(kdma_ch == NULL){
		printk(KERN_INFO "kdma transfer: failed to request dma chan\n");
		return -1;
	}
	printk(KERN_INFO "kdma transfer: dma channel name : %s", dma_chan_name(kdma_ch));
	_dev = kdma_ch->device;
	kdma_unmap_data = dmaengine_get_unmap_data(_dev->dev, 2, GFP_KERNEL);
	if(kdma_unmap_data == NULL){
		printk(KERN_INFO "kdma transfer: failed to get unmap data\n");
		return -1;
	}
	kdma_unmap_data->len = align_len;
	_page = virt_to_page(kdma_src);
	if(_page == NULL){
		printk(KERN_INFO "kdma transfer: failed to get page: 0\n");
		return -1;
	}
	_page_off = offset_in_page(kdma_src);
	kdma_unmap_data->addr[0] = dma_map_page(_dev->dev, _page, _page_off, align_len, DMA_TO_DEVICE);
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
	kdma_unmap_data->addr[1] = dma_map_page(_dev->dev, _page, _page_off, align_len, DMA_FROM_DEVICE);
	if(dma_mapping_error(_dev->dev, kdma_unmap_data->addr[1])){
		printk(KERN_INFO "kdma transfer: mappping error for dst\n");
		return -1;
	}
	kdma_unmap_data->from_cnt = 1;
	_dma_dstaddr = kdma_unmap_data->addr[1];

	_tx = _dev->device_prep_dma_memcpy(kdma_ch, _dma_dstaddr, _dma_srcaddr, align_len, DMA_CTRL_ACK);
	if(_tx == NULL){
		printk(KERN_INFO "kdma transfer: tx prep error\n");
		return -1;
	}
	_dma_cookie = _tx->tx_submit(_tx);
	if(dma_submit_error(_dma_cookie)){
		printk(KERN_INFO "kdma transfer: cookie error\n");
		return -1;
	}

	status = dma_sync_wait(kdma_ch, _dma_cookie);
	dmaengine_terminate_sync(kdma_ch);
	if (status != DMA_COMPLETE) {
		switch (status) {
			case DMA_IN_PROGRESS:
				printk(KERN_INFO "kdma transfer: DMA in progres...");
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
	}
	printk(KERN_INFO "kdma transfer: after dst: %d, src: %d", *(int *)dst, *(int *)src);
	dmaengine_unmap_put(kdma_unmap_data);
	dmaengine_terminate_sync(kdma_ch);
	dma_release_channel(kdma_ch);

	return 0;
}

static int __init mod_init(void)
{
	int *writer;
	printk(KERN_INFO "kdma: in init\n");

	src = kzalloc(16,GFP_KERNEL);
	dst = kzalloc(16,GFP_KERNEL);
	writer = (int *)src;
	*writer = 65;
	printk(KERN_INFO "kdma mod_init: before dst: %d, src: %d", *(int *)dst, *(int *)src);
	if(kdma_transfer(src, dst, 16) < 0){
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
    kfree(src);
	kfree(dst);
    printk(KERN_INFO "kdma mod_exit: done\n");
}

module_init(mod_init);
module_exit(mod_exit);

MODULE_AUTHOR("seantywork");
MODULE_LICENSE("GPL");
