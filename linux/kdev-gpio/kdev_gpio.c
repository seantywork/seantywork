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

#include <linux/gpio/driver.h>
#include <linux/gpio/consumer.h>

#define TARGET_LABEL "pinctrl-bcm2711"
#define TARGET_PIN_NAME	"GPIO17"


static int _gc_match(struct gpio_chip *gc, const void *data){
    int n = 0;
    if(gc->label != NULL){
        printk("kdev_gpio: label: %s\n", gc->label);
        if(strcmp(gc->label, TARGET_LABEL) == 0){
            printk("base: %d\n", gc->base);
            printk("ngpio: %d\n", gc->ngpio);
        }
    } else {
        printk("kdev_gpio: label: not available\n");
    }

    return 0;
}
static int __init kdev_gpio_init(void){
    gpio_device_find(NULL, _gc_match);

    return 0;
}

static void __exit kdev_gpio_exit(void){
    printk("kdev_gpio: bye\n");
}

module_init(kdev_gpio_init);
module_exit(kdev_gpio_exit);

MODULE_LICENSE("GPL");