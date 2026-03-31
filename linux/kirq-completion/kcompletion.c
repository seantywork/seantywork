#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/time.h>
#include <linux/delay.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>
#include <linux/kthread.h>	
#include <asm/atomic.h>
#include <linux/completion.h>
#include <linux/mutex.h>
#include <linux/signal.h>  
#include <linux/irqflags.h>

#define THREADS 4
#define TARGET_COUNT 10000


struct task_struct* kths[THREADS];
int kth_id[THREADS];
struct task_struct* kths_w[THREADS];
int kth_id_w[THREADS];

struct cond_t {
    atomic_t wait;
//    wait_queue_head_t wq;
    struct completion c;
};

struct cond_t comp;
struct mutex lock;
atomic_t wake_count;


int wake_threads(void* varg);
int wait_threads(void* varg);

int _sig_wait(struct cond_t* sig, struct mutex* lock);
void _sig_broadcast(struct cond_t* sig);


int _sig_wait(struct cond_t* sig, struct mutex* lock){
    mutex_unlock(lock);
    wait_for_completion_interruptible(&sig->c);
    reinit_completion(&sig->c);
    mutex_lock(lock);
    return 0;
}

void _sig_broadcast(struct cond_t* sig){
    complete_all(&sig->c);
}

int wake_threads(void* varg){
    int* id = (int*)varg;
    for(int i = 0; i < TARGET_COUNT; i++){
        printk(KERN_INFO "wake: %d ready...\n", *id);
        mutex_lock(&lock);
        _sig_broadcast(&comp);
        printk(KERN_INFO "wake: %d\n", *id);
        mutex_unlock(&lock);
    }
    return 0;
}

int wait_threads(void* varg){
    int* id = (int*)varg;
    while(!kthread_should_stop()){
        mutex_lock(&lock);
        _sig_wait(&comp, &lock);
        int v = atomic_inc_return(&wake_count);
        printk(KERN_INFO "thread: %d awaken!: %d\n", *id, v);
        mutex_unlock(&lock);
    }
    return 0;
}


static int __init this_wq_init(void){
    printk(KERN_INFO "this sig brd init\n");
    mutex_init(&lock);
    init_completion(&comp.c);
    atomic_set(&comp.wait, 0);
    atomic_set(&wake_count, 0);
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