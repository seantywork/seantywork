#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/timer.h>

static struct timer_list this_timer;

/*
void this_timer_callback(unsigned long data){


    printk(KERN_INFO "%s called: jiffies: %ld \n", __FUNCTION__, jiffies);
    
}
*/

void this_timer_callback(struct timer_list *timer){


    printk(KERN_INFO "%s called: jiffies: %ld \n", __FUNCTION__, jiffies);
    
}

static int __init this_init(void){

    int retval;

    printk("kstd timer init\n");

    //setup_timer(&this_timer, this_timer_callback, 0);

    timer_setup(&this_timer, this_timer_callback, 0);
    
    printk("set timer to trigger in 5000ms: jiffies: %ld\n", jiffies);

    retval = mod_timer(&this_timer, jiffies + msecs_to_jiffies(5000));

    if(retval){
        printk("timer setting failed\n");
    }

    return 0;

}

static void __exit this_exit(void){

    int retval;
    retval = del_timer(&this_timer);

    if(retval){
        printk("timer still in use\n");
    }

    printk("kstd timer unloaded\n");

}

module_init(this_init);
module_exit(this_exit);

MODULE_AUTHOR("seantywork");
MODULE_LICENSE("GPL");