#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/interrupt.h>

#define DEV_NAME    "DEV_NAME IRQ_1"
#define DEV_ID    	"DEV_ID"
// in vm, virtio
#define IRQ_1		1

MODULE_LICENSE("GPL");

void tasklet_function(struct tasklet_struct *tasklet_obj);

DECLARE_TASKLET(static_tasklet, tasklet_function);

int pressed_times = 0;

static irq_handler_t irq_1_handler(unsigned int irq, void* dev_id, struct pt_regs *regs){
	printk("Device ID %s; Keyboard interrupt occured %d\n", (char*)dev_id, pressed_times);
    pressed_times += 1;
	tasklet_schedule(&static_tasklet);

    return (irq_handler_t)IRQ_HANDLED;
}

int init_module(void)
{
	printk(KERN_INFO "hello, world !\n");
    if (request_irq(IRQ_1, (irq_handler_t)irq_1_handler, IRQF_SHARED, DEV_NAME, DEV_ID) != 0){
        printk("can't request interrupt number %d\n", IRQ_1);
    } else printk("requested interrupt number %d successfully\n", IRQ_1);

	return 0;
}

void cleanup_module(void)
{
	free_irq(IRQ_1, DEV_ID);
	tasklet_kill(&static_tasklet);
	printk(KERN_INFO "clean up module\n");
}

/* Bottom half tasklet handler */
void tasklet_function(struct tasklet_struct *tasklet_obj)
{

	printk("tasklet called\n");

	printk("tasklet: pressed time: %d\n", pressed_times);

	printk("tasklet done\n");

}

