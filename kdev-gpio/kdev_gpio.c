#include <linux/kernel.h>
#include <linux/init.h> 
#include <linux/module.h>
#include <linux/gpio.h>

#include <linux/slab.h> 
#include <linux/errno.h>  
#include <linux/types.h> 
#include <linux/interrupt.h> 

#include <linux/in.h>
#include <linux/string.h>
#include <linux/version.h> 

#include <linux/of.h>
#include <linux/of_gpio.h>
#include <linux/device.h>
#include <linux/container_of.h>
#include <linux/gpio/machine.h>
#include <linux/gpio/consumer.h>

#define TARGET_NAME	"GPIO17"

static int __init kdev_gpio_init(void){
    int n = 0;
    int gpio_target = 0;
    struct device_node* dn = NULL;
    struct device* d = NULL;
    struct gpio_desc* gd = NULL;
    dn = of_find_node_by_name(NULL, "gpio.0");
    if(dn == NULL){
        printk("failed to find device node: gpio\n");
        return -1;
    }
    d = container_of(&dn, struct device, of_node);
    if(IS_ERR(d)){
        printk("failed to get device from node\n");
        return -1;
    }
    gd = gpiod_get(d, "GPIO17", 0);
    if(IS_ERR(gd)){
        printk("failed to get desc\n");
        return -1;
    }
    printk("got desc\n");

    /*
    for(int i = 0; i < n; i++){
        gpio_target = of_get_named_gpio(dn, TARGET_NAME, i);
        printk("gpio_target: %d\n", gpio_target);
        if(gpio_target == -EPROBE_DEFER){
            printk("EPROBE DEFER\n");
            continue;
        }
        if(gpio_is_valid(gpio_target)){
            // deprecated
            //gpio_target = devm_gpio_request(d, gpio_target, TARGET_NAME);
            printk("SUCESS: gpio_target: %d\n", gpio_target);
        } else {
            printk("gpio is not valid\n");
            continue;
        }
    }
    */
    return 0;
}

static void __exit kdev_gpio_exit(void){
    printk("bye\n");
}

module_init(kdev_gpio_init);
module_exit(kdev_gpio_exit);

MODULE_LICENSE("GPL");