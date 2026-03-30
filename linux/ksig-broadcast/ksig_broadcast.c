#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/time.h>
#include <linux/delay.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>
#include <linux/kthread.h>	
//#include <asm/atomic.h>


#define THREADS 2



struct task_struct* kths[THREADS];
int kth_id[THREADS];
struct task_struct* kths_w[THREADS];
int kth_id_w[THREADS];

atomic_t awake;
int awake2 = 0;
wait_queue_head_t wq;
struct work_struct job[THREADS];

void wake_job(struct work_struct* work);
int wake_threads(void* varg);
int wait_threads(void* varg);

static inline bool atomic_compare_exchange(int* ptr, int compare, int exchange) {
    return __atomic_compare_exchange_n(ptr, &compare, exchange,
            0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
}
static inline void atomic_store(int* ptr, int value) {
    __atomic_store_n(ptr, value, __ATOMIC_SEQ_CST);
}

static inline int atomic_load(int* ptr) {
    return __atomic_load_n(ptr, __ATOMIC_SEQ_CST);
}

void wake_job(struct work_struct* work){
    printk(KERN_INFO "wake: waiting 5 seconds to wake all threads up...\n");
    mdelay(5000);
    printk(KERN_INFO "wake: wake job...\n");
//    atomic_set(&awake, 1);
    atomic_store(&awake2, 1);
    wake_up_interruptible_all(&wq);
}


int wake_threads(void* varg){
    int* id = (int*)varg;
    printk(KERN_INFO "wake: %d waiting 5 seconds to wake all threads up...\n", *id);
    mdelay(5000);
    printk(KERN_INFO "wake: %d: wake job...\n", *id);
    //atomic_set(&awake, 1);
    atomic_store(&awake2, 1);
    wake_up_interruptible_all(&wq);
    printk(KERN_INFO "wake: %d\n", *id);
    if(atomic_compare_exchange(&awake2, 1, 0)){
        printk(KERN_INFO "wake: %d: reset!\n", *id);
    } else {
        printk(KERN_INFO "wake: %d: done!\n", *id);
    }
    return 0;
}

int wait_threads(void* varg){
    int* id = (int*)varg;
    printk(KERN_INFO "thread: %d waiting...\n", *id);

    wait_event_interruptible(wq, atomic_load(&awake2));

    printk(KERN_INFO "thread: %d awaken!\n", *id);

    return 0;
}


int __init this_wq_init(void){
    printk(KERN_INFO "this sig brd init\n");
    init_waitqueue_head(&wq);
    //atomic_set(&awake, 0);
    atomic_store(&awake2, 0);
    for(int i = 0 ; i < THREADS; i++){
        kth_id[i] = i;
        kths[i] = kthread_run(wait_threads, (void*)&kth_id[i], "_th/%d", i);
        get_task_struct(kths[i]);
        //INIT_WORK(&job[i], wake_job);
        
        kth_id_w[i] = i;
        kths_w[i] = kthread_run(wake_threads, (void*)&kth_id_w[i], "_th_w/%d", i);
        get_task_struct(kths_w[i]);
        
    }
    /*
    for(int i = 0 ; i < THREADS; i++){
        schedule_work(&job[i]);
    }
    */
    /*
    msleep(5000);
    atomic_set(&awake, 1);
    wake_up_interruptible_all(&wq);
    */
    
    printk(KERN_INFO "this sig brd init done\n");
    return 0;
}

void __exit this_wq_exit(void){

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