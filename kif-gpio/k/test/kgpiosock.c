#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/gpio.h>
#include <linux/interrupt.h> /* IRQ */
#include <linux/sched.h>
#include <linux/time.h>
#include <linux/delay.h>
#include <linux/workqueue.h>

#define PIN_IN 539 // 27
#define PIN_OUT 530 // 18


static DECLARE_WAIT_QUEUE_HEAD(this_wq);
static int condition = 0;

static struct work_struct job;




static unsigned int irq_number;

static irqreturn_t gpio_irq_handler(int irq, void *dev_id) {
	printk("gpio_sock: interrupt was triggered and ISR was called.\n");
	return IRQ_HANDLED;
}

static void job_handler(struct work_struct* work){


    printk(KERN_INFO "waitqueue handler: %s\n", __FUNCTION__);

    msleep(5000);

    printk(KERN_INFO "wake this process up after 5000ms\n");

	gpio_set_value(PIN_OUT, 1);


	int gpioout = gpio_get_value(PIN_OUT);

	printk(KERN_INFO "gpio current state: %d\n", gpioout);

	msleep(1000);

	gpio_set_value(PIN_OUT, 0);

	gpioout = gpio_get_value(PIN_OUT);

	printk(KERN_INFO "gpio current state: %d\n", gpioout);

    condition = 1;

    wake_up_interruptible(&this_wq);


}

static int __init drv_init(void) {


	if(gpio_request(PIN_IN, "gpio-27-in")) {
		printk("gpio_sock: can't allocate GPIO 27\n");
		return -1;
	}

	if(gpio_request(PIN_OUT, "gpio-18-out")) {
		printk("gpio_sock: can't allocate GPIO 18\n");
		return -1;
	}

	if(gpio_direction_input(PIN_IN)) {
		printk("gpio_sock: can't set GPIO 27 to input\n");
		gpio_free(PIN_IN);
		return -1;
	}

	if(gpio_direction_output(PIN_OUT,0)) {
		printk("gpio_sock: can't set GPIO 18 to input\n");
		gpio_free(PIN_IN);
        gpio_free(PIN_OUT);
		return -1;
	}


	irq_number = gpio_to_irq(PIN_IN);


	if(request_irq(irq_number, gpio_irq_handler, IRQF_TRIGGER_RISING | IRQF_TRIGGER_FALLING, "gpio_sock0", NULL) != 0) {
		printk("gpio_sock: can't request interrupt %d.\n", irq_number);
		gpio_free(PIN_IN);
        gpio_free(PIN_OUT);
		return -1;
	}

/*
	if(request_irq(irq_number, gpio_irq_handler, IRQF_TRIGGER_RISING, "gpio_sock0", NULL) != 0) {
		printk("gpio_sock: can't request interrupt %d.\n", irq_number);
		gpio_free(PIN_IN);
        gpio_free(PIN_OUT);
		return -1;
	}
*/
	printk("gpio_sock: GPIO 27 is mapped to IRQ %d.\n", irq_number);

	printk("gpio_sock: module is initialized into the kernel.\n");

    INIT_WORK(&job, job_handler);

    schedule_work(&job);

    printk(KERN_INFO "putting to sleep: %s\n", __FUNCTION__);

    wait_event_interruptible(this_wq, condition != 0);

    printk(KERN_INFO "woken up\n");

	return 0;
}

static void __exit drv_exit(void) {

	gpio_free(PIN_IN);
    gpio_free(PIN_OUT);
    free_irq(irq_number, NULL);
	printk("gpio_sock: module is removed from the kernel.\n");
}

module_init(drv_init);
module_exit(drv_exit);

MODULE_LICENSE("GPL");