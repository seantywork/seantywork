#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/time.h>
#include <linux/delay.h>
#include <linux/workqueue.h>
#include <asm/atomic.h>
#include <linux/mutex.h>
#include <linux/kthread.h>	
#include <linux/spinlock.h>


#define MY_CPU_MAX 4
#define TARGET_COUNT 10000

struct my_work {
    int data;
    struct mutex mutex;
    spinlock_t spinlock;
    struct work_struct work;
};

atomic_t condition ;
struct my_work* mwrks;
struct task_struct* kth;

static void job_handler(struct work_struct* work){
    struct my_work* mw = container_of(work, struct my_work, work);
    int v = atomic_inc_return(&condition);
    printk(KERN_INFO "job handler: id: %d: %d\n", mw->data, v);
    mutex_unlock(&mw->mutex);
}

static int wake_thread(void* varg){
    int target = 0;
    for(int i = 0; i < TARGET_COUNT; i++){
        target = i % MY_CPU_MAX;
        printk(KERN_INFO "wake: %d ready...\n", i);
        mutex_lock(&mwrks[target].mutex);
        schedule_work_on(target, &mwrks[target].work);
        printk(KERN_INFO "wake: %d\n", i);
    }
    return 0;
}

static int __init this_wq_init(void){

    printk(KERN_INFO "this workqueue init\n");
    mwrks = kmalloc(sizeof(struct my_work) * MY_CPU_MAX, GFP_KERNEL);
    for(int i = 0; i < MY_CPU_MAX; i++){
        INIT_WORK(&mwrks[i].work, job_handler);
        mutex_init(&mwrks[i].mutex);
    }
    kth = kthread_run(wake_thread, NULL, "_th_w/%d", 0);
    get_task_struct(kth);
    printk(KERN_INFO "init done\n");

    return 0;
}

static void __exit this_wq_exit(void){
    kthread_stop(kth);
    kfree(mwrks);
    printk(KERN_INFO "this workqueue exit\n");

}

module_init(this_wq_init);
module_exit(this_wq_exit);

MODULE_AUTHOR("seantywork");
MODULE_LICENSE("GPL");