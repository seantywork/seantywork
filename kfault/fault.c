#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/time.h>
#include <linux/delay.h>
#include <linux/workqueue.h>

static DECLARE_WAIT_QUEUE_HEAD(this_wq);


static struct work_struct job;


static void job_handler(struct work_struct* work){

    u8 okay[16] = {0};

    u8* bomb = NULL;

    printk(KERN_INFO "waitqueue handler: %s\n", __FUNCTION__);

    printk(KERN_INFO "counting 5 seconds before light out\n");

    for(int i = 1; i <= 5; i++){

        printk(KERN_INFO "%d...\n", i);

        msleep(1000);
    }

    printk(KERN_INFO "GOODBYE, WORLD!!!!\n");

    
    for(int i = 0 ; i < 16; i++){

        if(okay[i] == bomb[i]){
            printk(KERN_INFO "equal at %d: %d\n", okay[i]);
        } else {
            printk(KERN_INFO "not equal at %d: %d != %d\n", okay[i], bomb[i]);
        }

    }

}

static int __init fault_init(void){

    printk(KERN_INFO "fault init\n");

    INIT_WORK(&job, job_handler);

    schedule_work(&job);

    return 0;
}

static void __exit fault_exit(void){

    printk(KERN_INFO "fault exit\n");

}

module_init(fault_init);
module_exit(fault_exit);

MODULE_AUTHOR("seantywork");
MODULE_LICENSE("GPL");