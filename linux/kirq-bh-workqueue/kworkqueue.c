#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/time.h>
#include <linux/delay.h>
#include <linux/workqueue.h>

static DECLARE_WAIT_QUEUE_HEAD(this_wq);
static int condition = 0;

static struct work_struct job;


static void job_handler(struct work_struct* work){


    printk(KERN_INFO "waitqueue handler: %s\n", __FUNCTION__);

    msleep(5000);

    printk(KERN_INFO "wake this process up after 5000ms\n");

    condition = 1;

    wake_up_interruptible(&this_wq);


}

static int __init this_wq_init(void){

    printk(KERN_INFO "this waitqueue init\n");

    INIT_WORK(&job, job_handler);

    schedule_work(&job);

    printk(KERN_INFO "putting to sleep: %s\n", __FUNCTION__);

    wait_event_interruptible(this_wq, condition != 0);

    printk(KERN_INFO "woken up\n");

    return 0;
}

static void __exit this_wq_exit(void){

    printk(KERN_INFO "this workqueue exit\n");

}

module_init(this_wq_init);
module_exit(this_wq_exit);

MODULE_AUTHOR("seantywork");
MODULE_LICENSE("GPL");