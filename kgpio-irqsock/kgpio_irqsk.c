#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/string.h>
#include <linux/gpio.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <linux/sched.h>
#include <linux/time.h>
#include <linux/delay.h>

static DECLARE_WAIT_QUEUE_HEAD(this_wq);

static int condition = 0;

static struct work_struct job;

static int gpio_ctl_o;
static int gpio_ctl_i;

module_param(gpio_ctl_o, int, 0664);
module_param(gpio_ctl_i, int, 0664);

static unsigned int gpio_ctl_i_irq;

static void job_handler(struct work_struct* work){


    printk(KERN_INFO "waitqueue handler: %s\n", __FUNCTION__);

    msleep(5000);

	gpio_set_value(gpio_ctl_o, IRQF_TRIGGER_RISING);

    printk(KERN_INFO "up after 5000ms\n");

    condition = 1;

    wake_up_interruptible(&this_wq);


}

static irqreturn_t gpio_irq_handler(int irq, void *dev_id) {
	printk("gpio irqsk: interrupt was triggered and ISR was called\n");
	return IRQ_HANDLED;
}

static int __init ksock_gpio_init(void) {

	if(gpio_request(gpio_ctl_o, "gpio-ctl-o")) {
		printk("gpio irqsk: can't allocate gpio_ctl_o: %d\n", gpio_ctl_o);
		return -1;
	}


	if(gpio_request(gpio_ctl_i, "gpio-ctl-i")) {
		printk("gpio irqsk: can't allocate gpio_ctl_i: %d\n", gpio_ctl_i);
		gpio_free(gpio_ctl_o);
		return -1;
	}

	if(gpio_direction_output(gpio_ctl_o, IRQF_TRIGGER_NONE)) {
		printk("gpio irqsk: can't set gpio_ctl_o to output\n");
		gpio_free(gpio_ctl_o);
		gpio_free(gpio_ctl_i);
		return -1;
	}

	if(gpio_direction_input(gpio_ctl_i)) {
		printk("gpio irqsk: can't set gpio_ctl_i to input\n");
		gpio_free(gpio_ctl_o);
		gpio_free(gpio_ctl_i);
		return -1;
	}

	gpio_ctl_i_irq = gpio_to_irq(gpio_ctl_i);

	if(request_irq(gpio_ctl_i_irq, gpio_irq_handler, IRQF_TRIGGER_RISING, "gpio_ctl_i_irq", NULL) != 0) {
		printk("gpio irqsk: can't request interrupt\n");
		gpio_free(gpio_ctl_o);
		gpio_free(gpio_ctl_i);
		return -1;
	}


	printk("gpio irqsk: gpio_ctl_i to IRQ %d\n", gpio_ctl_i_irq);

	printk("gpio irqsk: module is initialized into the kernel\n");

    INIT_WORK(&job, job_handler);

    schedule_work(&job);

    printk(KERN_INFO "putting to sleep: %s\n", __FUNCTION__);

    wait_event_interruptible(this_wq, condition != 0);

    printk(KERN_INFO "woken up\n");


	return 0;

}

static void __exit ksock_gpio_exit(void) {

	gpio_free(gpio_ctl_o);
	gpio_free(gpio_ctl_i);
	free_irq(gpio_ctl_i_irq, NULL);
	printk("gpio irqsk: module is removed from the kernel\n");
}

module_init(ksock_gpio_init);
module_exit(ksock_gpio_exit);

MODULE_LICENSE("GPL");