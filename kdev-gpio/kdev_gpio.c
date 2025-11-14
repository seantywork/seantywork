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

#define TARGET_NAME	"GPIO17"

static int __init kdev_gpio_init(void){
    int gpio_target = 0;
    struct device_node* dn = NULL;
    struct device* d = NULL;
    dn = of_find_node_by_name(NULL, "gpio0");
    if(dn == NULL){
        printk("failed to find device node: %s\n", TARGET_NAME);
        return -1;
    }
    gpio_target = of_get_named_gpio(dn, TARGET_NAME, 0);
    if(gpio_target == -EPROBE_DEFER){
        printk("EPROBE DEFER\n");
        return -1;
    }
    if(gpio_is_valid(gpio_target)){
        d = container_of(&dn, struct device, of_node);
        if(d == NULL){
            printk("failed to get device from node\n");
            return -1;
        }
        // deprecated
        //gpio_target = devm_gpio_request(d, gpio_target, TARGET_NAME);
        if(gpio_target){
            printk("SUCESS: gpio_target: %d\n", gpio_target);
        } else {
            printk("failed to request gpio target\n");
            return -1;
        }
    } else {
        printk("gpio is not valid\n");
        return -1;
    }
    

    return 0;
}

static void __exit kdev_gpio_exit(void){
    printk("bye\n");
}

module_init(kdev_gpio_init);
module_exit(kdev_gpio_exit);

MODULE_LICENSE("GPL");