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
#include <asm/atomic.h>
#include <linux/types.h>

#define CHECK_BIT(var,pos) ((var) & (1<<(pos)))

static DECLARE_WAIT_QUEUE_HEAD(this_wq);

static int condition = 0;

static struct work_struct job;

static int gpio_ctl_o;
static int gpio_ctl_i;
static int gpio_data_o;
static int gpio_data_i;

module_param(gpio_ctl_o, int, 0664);
module_param(gpio_ctl_i, int, 0664);
module_param(gpio_data_o, int, 0664);
module_param(gpio_data_i, int, 0664);

static unsigned int gpio_ctl_i_irq;
static unsigned int gpio_data_i_irq;

static int comms_mode_o = 0;

static int comms_mode_i = 0;
static int ctl_bits_count = 0;
static int data_bits_count = 0;

static u8 o_value = 200;
static u8 i_value = 0;

static void job_handler(struct work_struct* work){

    printk(KERN_INFO "waitqueue handler: %s\n", __FUNCTION__);

	for (int i = 0 ; i < 50; i++){

		printk(KERN_INFO "waitqueue handler waiting for: %d...\n", i);

		msleep(100);
	}

	printk(KERN_INFO "sending ctl start preamble\n");

	for(int i = 0; i < 3; i++){

		gpio_set_value(gpio_ctl_o, IRQF_TRIGGER_RISING);

		gpio_set_value(gpio_ctl_o, IRQF_TRIGGER_NONE);

		udelay(512);
	}

	gpio_set_value(gpio_data_o, IRQF_TRIGGER_RISING);

	gpio_set_value(gpio_data_o, IRQF_TRIGGER_NONE);
	
	udelay(512);

	for(int i = 0; i < 8; i++){

		if(CHECK_BIT(o_value, i)){

			if(!comms_mode_o){

				gpio_set_value(gpio_ctl_o, IRQF_TRIGGER_RISING);

				gpio_set_value(gpio_ctl_o, IRQF_TRIGGER_NONE);

				comms_mode_o = 1;
			}

			gpio_set_value(gpio_data_o, IRQF_TRIGGER_RISING);

			gpio_set_value(gpio_data_o, IRQF_TRIGGER_NONE);


		} else {

			if(comms_mode_o){
				
				gpio_set_value(gpio_ctl_o, IRQF_TRIGGER_RISING);

				gpio_set_value(gpio_ctl_o, IRQF_TRIGGER_NONE);

				comms_mode_o = 0;
			}

			gpio_set_value(gpio_data_o, IRQF_TRIGGER_RISING);

			gpio_set_value(gpio_data_o, IRQF_TRIGGER_NONE);

		}
		udelay(512);
	}

	printk(KERN_INFO "sending ctl trailer\n");

	for(int i = 0; i < 3; i++){

		gpio_set_value(gpio_ctl_o, IRQF_TRIGGER_RISING);

		gpio_set_value(gpio_ctl_o, IRQF_TRIGGER_NONE);

		udelay(512);
	}
	

	gpio_set_value(gpio_data_o, IRQF_TRIGGER_RISING);

	gpio_set_value(gpio_data_o, IRQF_TRIGGER_NONE);

	udelay(512);

    printk(KERN_INFO "up\n");

    condition = 1;

    wake_up_interruptible(&this_wq);


}

static irqreturn_t gpio_ctl_irq_handler(int irq, void *dev_id) {
	printk("gpio irqsk: ctl interrupt\n");
	ctl_bits_count += 1;
	printk("gpio irqsk: ctl bits count: %d\n", ctl_bits_count);

	return IRQ_HANDLED;
}

static irqreturn_t gpio_data_irq_handler(int irq, void *dev_id) {
	printk("gpio irqsk: data interrupt\n");

	if(ctl_bits_count == 3){
		ctl_bits_count = 0;
		if(data_bits_count == 0){
			printk("gpio irqsk: data preamble\n");
			return IRQ_HANDLED;
		} else {
			printk("gpio irqsk: data trailer\n");
			// skb
			printk("gpio irqsk: read result: %u\n", i_value);
			data_bits_count = 0;
			return IRQ_HANDLED;
		}
	}

	if(ctl_bits_count == 1){
		ctl_bits_count = 0;
		if(comms_mode_i){
			comms_mode_i = 0;
		} else {
			comms_mode_i = 1;
		}
	}

	if(comms_mode_i){

		i_value = i_value | (1 << data_bits_count);

	} else {

		i_value = i_value | (0 << data_bits_count);

	}

	data_bits_count += 1;

	printk("gpio irqsk: data bits count: %d\n", data_bits_count);
	return IRQ_HANDLED;
}

static int __init ksock_gpio_init(void) {

	if(gpio_ctl_o == 0 && gpio_ctl_i == 0){

		printk("gpio irqsk: at least one ctl should be set\n");
		return -1;

	}

	if(gpio_ctl_o != 0){

		if(gpio_data_o == 0){
			printk("gpio irqsk: gpio_ctl_o should also set gpio_data_o\n");
			return -1;
		}

		if(gpio_request(gpio_ctl_o, "gpio-ctl-o")) {
			printk("gpio irqsk: can't allocate gpio_ctl_o: %d\n", gpio_ctl_o);
			return -1;
		}		

		if(gpio_direction_output(gpio_ctl_o, IRQF_TRIGGER_NONE)) {
			printk("gpio irqsk: can't set gpio_ctl_o to output\n");
			gpio_free(gpio_ctl_o);
			return -1;
		}

		if(gpio_request(gpio_data_o, "gpio-data-o")) {
			printk("gpio irqsk: can't allocate gpio_data_o: %d\n", gpio_data_o);
			gpio_free(gpio_ctl_o);
			return -1;
		}		

		if(gpio_direction_output(gpio_data_o, IRQF_TRIGGER_NONE)) {
			printk("gpio irqsk: can't set gpio_data_o to output\n");
			gpio_free(gpio_ctl_o);
			gpio_free(gpio_data_o);
			return -1;
		}
	}

	if(gpio_ctl_i != 0){

		if(gpio_data_i == 0){
			printk("gpio irqsk: gpio_ctl_i should also set gpio_data_i\n");
			if(gpio_ctl_o != 0){
				gpio_free(gpio_ctl_o);
				gpio_free(gpio_data_o);
			}
			return -1;
		}

		if(gpio_request(gpio_ctl_i, "gpio-ctl-i")) {
			printk("gpio irqsk: can't allocate gpio_ctl_i: %d\n", gpio_ctl_i);
			if(gpio_ctl_o != 0){
				gpio_free(gpio_ctl_o);
				gpio_free(gpio_data_o);
			}
			return -1;
		}


		if(gpio_direction_input(gpio_ctl_i)) {
			printk("gpio irqsk: can't set gpio_ctl_i to input\n");
			if(gpio_ctl_o != 0){
				gpio_free(gpio_ctl_o);
				gpio_free(gpio_data_o);
			}
			gpio_free(gpio_ctl_i);
			return -1;
		}

		if(gpio_request(gpio_data_i, "gpio-data-i")) {
			printk("gpio irqsk: can't allocate gpio_data_i: %d\n", gpio_data_i);
			if(gpio_ctl_o != 0){
				gpio_free(gpio_ctl_o);
				gpio_free(gpio_data_o);
			}
			gpio_free(gpio_ctl_i);
			return -1;
		}


		if(gpio_direction_input(gpio_data_i)) {
			printk("gpio irqsk: can't set gpio_data_i to input\n");
			if(gpio_ctl_o != 0){
				gpio_free(gpio_ctl_o);
				gpio_free(gpio_data_o);
			}
			gpio_free(gpio_ctl_i);
			gpio_free(gpio_data_i);
			return -1;
		}


		gpio_ctl_i_irq = gpio_to_irq(gpio_ctl_i);

		if(request_irq(gpio_ctl_i_irq, gpio_ctl_irq_handler, IRQF_TRIGGER_RISING, "gpio_ctl_i_irq", NULL) != 0) {
			printk("gpio irqsk: can't request interrupt\n");
			if(gpio_ctl_o != 0){
				gpio_free(gpio_ctl_o);
				gpio_free(gpio_data_o);
			}
			gpio_free(gpio_ctl_i);
			gpio_free(gpio_data_i);
			return -1;
		}

		gpio_data_i_irq = gpio_to_irq(gpio_data_i);

		if(request_irq(gpio_data_i_irq, gpio_data_irq_handler, IRQF_TRIGGER_RISING, "gpio_data_i_irq", NULL) != 0) {
			printk("gpio irqsk: can't request interrupt\n");
			if(gpio_ctl_o != 0){
				gpio_free(gpio_ctl_o);
				gpio_free(gpio_data_o);
			}
			gpio_free(gpio_ctl_i);
			gpio_free(gpio_data_i);
			free_irq(gpio_ctl_i_irq, NULL);
			return -1;
		}

		printk("gpio irqsk: gpio_ctl_i to IRQ %d\n", gpio_ctl_i_irq);

		printk("gpio irqsk: gpio_data_i to IRQ %d\n", gpio_data_i_irq);
	}

	printk("gpio irqsk: module is initialized into the kernel\n");

	printk("gpio irqsk: ctl_o: %d ctl_i: %d\n", gpio_ctl_o, gpio_ctl_i);
	printk("gpio irqsk: data_o: %d data_i: %d\n", gpio_data_o, gpio_data_i);
	

	if(gpio_ctl_o != 0 && gpio_ctl_i == 0){

		printk("gpio irqsk: test mode\n");

		INIT_WORK(&job, job_handler);

		schedule_work(&job);

		printk(KERN_INFO "putting to sleep: %s\n", __FUNCTION__);

		wait_event_interruptible(this_wq, condition != 0);

		printk(KERN_INFO "woken up\n");

	}


	return 0;

}

static void __exit ksock_gpio_exit(void) {

	if(gpio_ctl_o != 0){

		gpio_free(gpio_ctl_o);
		gpio_free(gpio_data_o);
	}
	if(gpio_ctl_i != 0){
		gpio_free(gpio_ctl_i);
		gpio_free(gpio_data_i);
		free_irq(gpio_ctl_i_irq, NULL);
		free_irq(gpio_data_i_irq, NULL);
	}

	printk("gpio irqsk: module is removed from the kernel\n");
}

module_init(ksock_gpio_init);
module_exit(ksock_gpio_exit);

MODULE_LICENSE("GPL");