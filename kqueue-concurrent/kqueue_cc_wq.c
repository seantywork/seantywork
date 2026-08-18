#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/time.h>
#include <linux/delay.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>
#include <linux/kthread.h>	
#include <linux/completion.h>
#include <linux/irqflags.h>



#define TESTCASE 10000
#define THREADS 4

typedef struct testdata {
    uint32_t top;
    uint32_t bottom;
} testdata;

struct ccq {
    int id;
    uint32_t tcount;
    uint32_t tcurrent;
    testdata data;
    struct mutex mutex;
    struct work_struct work;
};


struct task_struct* kthen[THREADS];
struct ccq ccq;
atomic_t enq_result;
atomic_t deq_result;

static void enqueue(struct ccq* q, void* data, uint32_t datalen){
    uint32_t target = 0;
    mutex_lock(&q->mutex);
    target = q->tcurrent % q->tcount;
    q->tcurrent += 1; 
    memcpy(&q->data, data, datalen);
    q->id = target;
    schedule_work_on(target, &q->work);
}
static void do_dequeue(struct work_struct* work){
    testdata td;
    struct ccq* q = container_of(work, struct ccq, work);
    memcpy(&td, &q->data, sizeof(testdata));
    atomic_add(td.top + td.bottom, &deq_result);
    mutex_unlock(&q->mutex);
}

static int do_enqueue(void* varg){
    testdata td;
    printk(KERN_INFO "e: start\n");
    for(int i = 0 ; i < TESTCASE; i++){
        td.top = i + 1;
        td.bottom =  i + 1;
        atomic_add(td.top + td.bottom, &enq_result);
        enqueue(&ccq, &td, sizeof(testdata));
    }
    printk(KERN_INFO "e: done\n");
    return 0;
}



static int __init this_wq_init(void){
    printk(KERN_INFO "this ccq init\n");
    INIT_WORK(&ccq.work, do_dequeue);
    mutex_init(&ccq.mutex);
    ccq.tcount = THREADS;
    ccq.tcurrent = 0;
    for(int i = 0 ; i < THREADS; i++){
        kthen[i] = kthread_run(do_enqueue, NULL, "_testen/%d", i);
        get_task_struct(kthen[i]);
    }
    printk(KERN_INFO "init done\n");

    return 0;
}

static void __exit this_wq_exit(void){

    printk(KERN_INFO "this ccq exit\n");
    printk(KERN_INFO "enq, deq result: %d, %d\n", atomic_read(&enq_result), atomic_read(&deq_result));
    for(int i = 0 ; i < THREADS; i++){
        kthread_stop(kthen[i]);
    }
    printk(KERN_INFO "ext done\n");

}

module_init(this_wq_init);
module_exit(this_wq_exit);

MODULE_AUTHOR("seantywork");
MODULE_LICENSE("GPL");