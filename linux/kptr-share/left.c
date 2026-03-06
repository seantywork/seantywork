#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>	
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/workqueue.h>

typedef struct left_messsage_shared {
    char* message;
    struct mutex lock;  
} left_messsage_shared;

int left_condition = 1;
static DECLARE_WAIT_QUEUE_HEAD(left_wait);
struct work_struct left_job;

left_messsage_shared* lms = NULL;

void left_job_handler(struct work_struct* w){
    while(left_condition){
        if(lms != NULL){
            mutex_lock(&lms->lock);
            printk("LEFT ADDR: %px\n", (void*)&lms);
            if(lms->message != NULL){
                printk("LEFT: %s\n", lms->message);
            }
            mutex_unlock(&lms->lock);
        }
        msleep(2000);
    }
    printk("LEFT: job exit\n");
    left_condition = 2;
    wake_up_interruptible(&left_wait);
}

left_messsage_shared** get_left_message_address(void){
    return &lms;
}

EXPORT_SYMBOL_GPL(get_left_message_address);

static int __init left_init(void){
    lms = (left_messsage_shared*)kzalloc(sizeof(left_messsage_shared), GFP_KERNEL);
    if(lms == NULL){
        printk("failed to allocate left message shared\n");
        return -ENOMEM;
    }
    lms->message = (char*)kzalloc(1024, GFP_KERNEL);
    if(lms->message == NULL){
        printk("failed to allocate left message valud\n");
        kfree(lms);
        return -ENOMEM;
    }
    strcpy(lms->message, "left message");
    mutex_init(&lms->lock);
    INIT_WORK(&left_job, left_job_handler);
    schedule_work(&left_job);
    printk("init: left job scheduled\n");
    return 0;
}

static void __exit left_exit(void){

    printk("exit: left exiting, wait for job completion...\n");
    left_condition = 0;
    wait_event_interruptible(left_wait, left_condition == 2);
    printk("exit: left exiting, wait done\n");
    if(lms != NULL){
        mutex_destroy(&lms->lock);
        kfree(lms->message);
        kfree(lms);        
    }
    printk("exit: left done\n");
}

module_init(left_init);
module_exit(left_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("seantywork");