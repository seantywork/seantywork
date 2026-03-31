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

struct cond_t {
//    atomic_t awake;
//    wait_queue_head_t wq;
    struct completion c;
};

typedef struct ccq_node ccq_node;

struct ccq_node {
    uint32_t datalen;
    uint8_t in_use;
    uint8_t rsvd[3];
	void* data;
	ccq_node* prev;
	ccq_node* next;
};

typedef struct ccq_bucket {
	uint32_t limit;
	struct mutex lock;
	struct cond_t sig;
	ccq_node* qhead;
	ccq_node* qtail;
} ccq_bucket;

void _sig_init(struct cond_t* sig);
void _sig_wait(struct cond_t* sig, struct mutex* lock);
void _sig_broadcast(struct cond_t* sig);
ccq_bucket* make_queue(uint32_t datalen, int max);
void delete_queue(ccq_bucket* q);
void enqueue(ccq_bucket* q, void* data, uint32_t datalen);
void dequeue(ccq_bucket* q, void* data, uint32_t datalen);


void _sig_init(struct cond_t* sig){
//    atomic_set(&sig->awake, 0);
//    init_waitqueue_head(&sig->wq);
    init_completion(&sig->c);
}

void _sig_wait(struct cond_t* sig, struct mutex* lock){
    mutex_unlock(lock);
    //wait_event(sig->wq, atomic_cmpxchg(&sig->awake, 1, 0));
    //wait_for_completion_interruptible(&sig->c);
    wait_for_completion_timeout(&sig->c, HZ / 100);
    reinit_completion(&sig->c);
    /*
    while(!atomic_read(&sig->awake)){
        ndelay(1000);
    }    
    atomic_set(&sig->awake, 0);
    */
    mutex_lock(lock);
}

void _sig_broadcast(struct cond_t* sig){
//    atomic_set(&sig->awake, 1);
    complete_all(&sig->c);
}

#define TESTCASE 100000
#define BUFFSIZE 2048
#define EN_QUEUES 4
#define DE_QUEUES 4

struct thdata {
    int id;
    ccq_bucket* q;
};

typedef struct testdata {
    uint32_t top;
    uint32_t bottom;
} testdata;

struct task_struct* kthen[EN_QUEUES];
struct task_struct* kthde[DE_QUEUES];
struct thdata tden[EN_QUEUES];
struct thdata tdde[DE_QUEUES];
ccq_bucket* gq = NULL;
atomic_t enq_result;
atomic_t deq_result;

ccq_bucket* make_queue(uint32_t datalen, int max){
    ccq_bucket* q = (ccq_bucket*)kmalloc(sizeof(ccq_bucket), GFP_KERNEL);
    memset(q, 0, sizeof(ccq_bucket));
    mutex_init(&q->lock);
    _sig_init(&q->sig);
    for(int i = 0; i < max; i++){
        ccq_node* n = (ccq_node*)kmalloc(sizeof(ccq_node), GFP_KERNEL);
        memset(n, 0, sizeof(ccq_node));
        n->data = kmalloc(datalen, GFP_KERNEL);
        n->datalen = datalen;
        if(i == 0){
            q->qhead = n;
            q->qtail = n;
        } else {
            q->qtail->next = n;
            q->qtail = q->qtail->next;
        }
    }
    q->qtail->next = q->qhead;
    q->qtail = q->qhead;
    q->limit = max;
    return q;
}


void delete_queue(ccq_bucket* q){
    if(q == NULL){
        return;
    }
    ccq_node* data = q->qhead;
    mutex_lock(&q->lock);
    for(int i = 0; i < q->limit; i++){
        ccq_node* tmp = data->next;
        kfree(data->data);
        kfree(data);
        data = tmp;
    }
    mutex_unlock(&q->lock);
    kfree(q);
}

void enqueue(ccq_bucket* q, void* data, uint32_t datalen){
    for(;;){
        mutex_lock(&q->lock);
        if((q->qhead == q->qtail) && (q->qhead->in_use == 1)){
            _sig_wait(&q->sig, &q->lock);
            if((q->qhead == q->qtail) && (q->qhead->in_use == 1)){
                mutex_unlock(&q->lock);
                continue;
            }
        }
        memcpy(q->qtail->data, data, q->qtail->datalen);
        if((q->qhead == q->qtail) && (q->qhead->in_use != 1)){
            _sig_broadcast(&q->sig);
        }
        q->qtail->in_use = 1;
        q->qtail = q->qtail->next;
        mutex_unlock(&q->lock);
        break;
    }
}
void dequeue(ccq_bucket* q, void* data, uint32_t datalen){
    for(;;){
        mutex_lock(&q->lock);
        if((q->qhead == q->qtail) && (q->qhead->in_use != 1)){
            _sig_wait(&q->sig, &q->lock);
            if((q->qhead == q->qtail) && (q->qhead->in_use != 1)){
                mutex_unlock(&q->lock);
                continue;
            }
        }
        memcpy(data, q->qhead->data, q->qhead->datalen);
        if((q->qhead == q->qtail) && (q->qhead->in_use == 1)){
            _sig_broadcast(&q->sig);
        }
        q->qhead->in_use = 0;
        q->qhead = q->qhead->next;
        mutex_unlock(&q->lock);
        break;
    }
}

static int do_enqueue(void* varg){
    testdata td;
    struct thdata* thd = (struct thdata*)varg;
    ccq_bucket* q = thd->q;
    printk(KERN_INFO "e: %d start\n", thd->id);
    for(int i = 0 ; i < TESTCASE; i++){
        td.top = i + 1;
        td.bottom =  i + 1;
        atomic_add(td.top + td.bottom, &enq_result);
        enqueue(q, &td, sizeof(testdata));
    }
    printk(KERN_INFO "e: %d done\n", thd->id);
    return 0;
}

static int do_dequeue(void* varg){
    int counter = 0;
    testdata td;
    struct thdata* thd = (struct thdata*)varg;
    ccq_bucket* q = thd->q;
    printk(KERN_INFO "d: %d start\n", thd->id);
    for(;counter < TESTCASE;){
        dequeue(q, &td, sizeof(testdata));
        atomic_add(td.top + td.bottom, &deq_result);
        counter += 1;
    }
    printk(KERN_INFO "d: %d done\n", thd->id);
    return 0;
}

static int __init this_wq_init(void){
    printk(KERN_INFO "this ccq init\n");
    gq = make_queue(sizeof(testdata), BUFFSIZE);
    for(int i = 0 ; i < EN_QUEUES; i++){
        tden[i].id = i;
        tden[i].q = gq;
        kthen[i] = kthread_run(do_enqueue, (void*)&tden[i], "_testen/%d", i);
        get_task_struct(kthen[i]);
    }
    for(int i = 0; i < DE_QUEUES; i++){
        tdde[i].id = i;
        tdde[i].q = gq;
        kthde[i] = kthread_run(do_dequeue, (void*)&tdde[i], "_testde/%d", i);
        get_task_struct(kthde[i]);
    }
    printk(KERN_INFO "init done\n");

    return 0;
}

static void __exit this_wq_exit(void){

    printk(KERN_INFO "this ccq exit\n");
    printk(KERN_INFO "enq, deq result: %d, %d\n", atomic_read(&enq_result), atomic_read(&deq_result));
    delete_queue(gq);
    for(int i = 0 ; i < EN_QUEUES; i++){
        kthread_stop(kthen[i]);
    }
    for(int i = 0; i < DE_QUEUES; i++){
        kthread_stop(kthde[i]);
    }
    printk(KERN_INFO "ext done\n");

}

module_init(this_wq_init);
module_exit(this_wq_exit);

MODULE_AUTHOR("seantywork");
MODULE_LICENSE("GPL");