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

#include <linux/device.h>
#include <linux/of.h>
#include <linux/of_gpio.h>
#include <linux/gpio/driver.h>
#include <linux/gpio/consumer.h>

#define TARGET_NODE_NAME "gpiodt_pin_17"
struct device_node* dn = NULL;


static int __init kdev_gpio_init(void){
    dn = of_find_node_by_name(NULL, TARGET_NODE_NAME);
    if(dn == NULL){
        printk("failed to get node by name\n");
        return -1;
    }
    printk("kdev_gpio: got node by name\n");
    if(dn->properties != NULL){
        struct property* p = dn->properties;
        while(1){
            if(p->name != NULL){
                printk("p name: %s\n", p->name);
            }
            p = p->next;
            if(p == NULL){
                break;
            }
        }
    }
    struct device* d = container_of(&dn,struct device, of_node);
    if(d == NULL){
        of_node_put(dn);
        printk("failed to get device\n");
        return -1;
    }
    if(d->init_name != NULL){
        printk("device init name: %s\n", d->init_name);
    }
    struct gpio_chip* gc = container_of(&d,struct gpio_chip, parent);
    if(gc != NULL){
        printk("got gc\n");
        if(gc->label != NULL){
            printk("gc label: %d\n", gc->base);
        }
    }

    printk("kdev_gpio: init\n");
    return 0;
}

static void __exit kdev_gpio_exit(void){
    if(dn != NULL){
        of_node_put(dn);
    }

    printk("kdev_gpio: bye\n");
}

module_init(kdev_gpio_init);
module_exit(kdev_gpio_exit);

MODULE_LICENSE("GPL");