#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/gpio.h>
#include <linux/interrupt.h> /* IRQ */

#define PIN_IN 539 // 27
#define PIN_OUT 530 // 18

MODULE_LICENSE("GPL");

static unsigned int irq_number;

static irqreturn_t gpio_irq_handler(int irq, void *dev_id) {
	printk("gpio_sock: interrupt was triggered and ISR was called.\n");
	return IRQ_HANDLED;
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
	printk("gpio_sock: GPIO 27 is mapped to IRQ %d.\n", irq_number);

	printk("gpio_sock: module is initialized into the kernel.\n");
	return 0;
}

static void __exit drv_exit(void) {
	printk("gpio_sock: module is removed from the kernel.\n");
	gpio_free(PIN_IN);
    gpio_free(PIN_OUT);
    free_irq(irq_number, NULL);
}

module_init(drv_init);
module_exit(drv_exit);