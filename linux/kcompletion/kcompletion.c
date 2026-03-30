#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/time.h>
#include <linux/delay.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>
#include <linux/kthread.h>	
//#include <asm/atomic.h>
#include <linux/completion.h>

#define THREADS 4



struct task_struct* kths[THREADS];
int kth_id[THREADS];
struct task_struct* kths_w[THREADS];
int kth_id_w[THREADS];

struct completion comp;


int wake_threads(void* varg);
int wait_threads(void* varg);




int wake_threads(void* varg){
    int* id = (int*)varg;
    int wsec = (*id) + 1;
    printk(KERN_INFO "wake: %d waiting %d seconds to wake all threads up...\n", *id, wsec);
    mdelay(1000);
    printk(KERN_INFO "wake: %d: wake job...\n", *id);
    complete_all(&comp);
    printk(KERN_INFO "wake: %d\n", *id);
    return 0;
}

int wait_threads(void* varg){
    int* id = (int*)varg;
    printk(KERN_INFO "thread: %d waiting...\n", *id);
    wait_for_completion_timeout(&comp, HZ / 100);
    printk(KERN_INFO "thread: %d awaken!\n", *id);
    return 0;
}


static int __init this_wq_init(void){
    printk(KERN_INFO "this sig brd init\n");
    init_completion(&comp);
    for(int i = 0 ; i < THREADS; i++){
        kth_id[i] = i;
        kths[i] = kthread_run(wait_threads, (void*)&kth_id[i], "_th/%d", i);
        get_task_struct(kths[i]);
        
        kth_id_w[i] = i;
        kths_w[i] = kthread_run(wake_threads, (void*)&kth_id_w[i], "_th_w/%d", i);
        get_task_struct(kths_w[i]);
        
    }
    
    printk(KERN_INFO "this sig brd init done\n");
    return 0;
}

static void __exit this_wq_exit(void){

    printk(KERN_INFO "this sig brd exit\n");
    for(int i = 0 ; i < THREADS; i++){
        kthread_stop(kths[i]);
        kthread_stop(kths_w[i]);
    }
    
    printk(KERN_INFO "ext done\n");

}

module_init(this_wq_init);
module_exit(this_wq_exit);

MODULE_AUTHOR("seantywork");
MODULE_LICENSE("GPL");