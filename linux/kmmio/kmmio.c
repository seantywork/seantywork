#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/io.h>
#include <linux/ioport.h>

#define MY_PHYSADDR 0x7e200000 // rpi gpio dma addr
#define MY_REGION 164 // rpi gpio dma region size

static int mreq = 0;
static void __iomem* src = NULL;
static void __iomem* dst = NULL;

static int __init mod_init(void)
{
    if(!request_mem_region(MY_PHYSADDR, MY_REGION, "mydriver")){
        printk(KERN_INFO "failed to get addr\n");
        return -EINVAL;
    }
    src = ioremap(MY_PHYSADDR, MY_REGION);
    if(src == NULL){
        printk(KERN_INFO "failed to map\n");
        return -EINVAL;
    }
    mreq = 1;
	return 0;
}


static void __exit mod_exit(void)
{
    printk(KERN_INFO "kmmio mod_exit: mod_exit called\n");
	if(src != NULL){
        iounmap(src);
    }
    if(dst != NULL){
        iounmap(dst);
    }
    if(mreq){
        release_mem_region(MY_PHYSADDR, MY_REGION);
    }
    printk(KERN_INFO "kmmio mod_exit: done\n");
}



module_init(mod_init);
module_exit(mod_exit);

MODULE_AUTHOR("seantywork");
MODULE_LICENSE("GPL");
