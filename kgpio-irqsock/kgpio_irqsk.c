#include "kgpio_irqsk.h"


DECLARE_WAIT_QUEUE_HEAD(this_wq);

int condition = 0;

struct work_struct job;

int gpio_ctl_o;
int gpio_ctl_i;
int gpio_data_o;
int gpio_data_i;

module_param(gpio_ctl_o, int, 0664);
module_param(gpio_ctl_i, int, 0664);
module_param(gpio_data_o, int, 0664);
module_param(gpio_data_i, int, 0664);

unsigned int gpio_ctl_i_irq;
unsigned int gpio_data_i_irq;

int comms_mode_o = 0;

int comms_mode_i = 0;
int ctl_bits_count = 0;
int data_bits_count = 0;

u8 o_value[MAX_PKTLEN] = {0};
u8 i_value[MAX_PKTLEN] = {0};


void gpio_ctl_on(void){

	gpio_set_value(gpio_ctl_o, IRQF_TRIGGER_RISING);

	udelay(16);

	gpio_set_value(gpio_ctl_o, IRQF_TRIGGER_NONE);
}

void gpio_data_on(void){

	gpio_set_value(gpio_data_o, IRQF_TRIGGER_RISING);

	udelay(16);

	gpio_set_value(gpio_data_o, IRQF_TRIGGER_NONE);

}

void job_handler(struct work_struct* work){

    printk(KERN_INFO "waitqueue handler: %s\n", __FUNCTION__);

	printk(KERN_INFO "waitqueue handler waiting...\n");

	msleep(100);

	printk(KERN_INFO "sending ctl start preamble\n");

	for(int i = 0; i < 3; i++){

		gpio_ctl_on();
	}

	gpio_data_on();


	for(int i = 0; i < MAX_PKTLEN; i++) {

		for(int j = 0; j < 8; j++){

			if(CHECK_BIT(o_value[i], j)){

				if(!comms_mode_o){

					gpio_ctl_on();

					comms_mode_o = 1;
				}

				gpio_data_on();

			} else {

				if(comms_mode_o){
					
					gpio_ctl_on();

					comms_mode_o = 0;
				}

				gpio_data_on();

			}

		}

	}

	printk(KERN_INFO "sending ctl trailer\n");

	for(int i = 0; i < 3; i++){

		gpio_ctl_on();
	}
	
	gpio_data_on();

    condition = 1;

    wake_up_interruptible(&this_wq);

}

irqreturn_t gpio_ctl_irq_handler(int irq, void *dev_id) {
	ctl_bits_count += 1;
	return IRQ_HANDLED;
}

irqreturn_t gpio_data_irq_handler(int irq, void *dev_id) {

	int pktidx = 0;
	int bitidx = 0;

	if(ctl_bits_count == 3){
		ctl_bits_count = 0;
		if(data_bits_count == 0){
			return IRQ_HANDLED;
		} else {
			// skb
			printk("value: %02x%02x%02x%02x...%02x%02x%02x%02x\n", 
				i_value[0],
				i_value[1],
				i_value[2],
				i_value[3],
				i_value[MAX_PKTLEN-4],
				i_value[MAX_PKTLEN-3],
				i_value[MAX_PKTLEN-2],
				i_value[MAX_PKTLEN-1]
			);
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

	pktidx = data_bits_count / 8;
	bitidx = data_bits_count % 8;

	if(comms_mode_i){

		i_value[pktidx] = i_value[pktidx] | (1 << bitidx);

	} else {

		i_value[pktidx] = i_value[pktidx] | (0 << bitidx);

	}

	data_bits_count += 1;

	return IRQ_HANDLED;
}

int __init ksock_gpio_init(void) {

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

		get_random_bytes(o_value, MAX_PKTLEN);

		printk("value: %02x%02x%02x%02x...%02x%02x%02x%02x\n", 
			o_value[0],
			o_value[1],
			o_value[2],
			o_value[3],
			o_value[MAX_PKTLEN-4],
			o_value[MAX_PKTLEN-3],
			o_value[MAX_PKTLEN-2],
			o_value[MAX_PKTLEN-1]
		);
		INIT_WORK(&job, job_handler);

		for(int i = 0; i < 10; i++){
			schedule_work(&job);

			wait_event_interruptible(this_wq, condition != 0);

			condition = 0;
		}

		printk(KERN_INFO "job done\n");

	}


	return 0;

}

void __exit ksock_gpio_exit(void) {

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