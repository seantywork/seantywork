#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/interrupt.h>

#define DEV_NAME    "kirq_key"
#define DEV_ID    	"0001"
// in vm, virtio
#define IRQ_1		1

MODULE_LICENSE("GPL");

int pressed_times = 0;


static irq_handler_t irq_1_handler(unsigned int irq, void* dev_id, struct pt_regs *regs){
	printk("Device ID %s; Keyboard interrupt occured %d\n", (char*)dev_id, pressed_times);

    pressed_times += 1;

    return (irq_handler_t)IRQ_HANDLED;
}

int init_module(void)
{
	printk(KERN_INFO "top halves module\n");
    if (request_irq(IRQ_1, (irq_handler_t)irq_1_handler, IRQF_SHARED, DEV_NAME, DEV_ID) != 0){
        printk("can't request interrupt number %d\n", IRQ_1);
    } else printk("requested interrupt number %d successfully\n", IRQ_1);

	return 0;
}

void cleanup_module(void)
{
	free_irq(IRQ_1, DEV_ID);
	printk(KERN_INFO "clean up module\n");
}
