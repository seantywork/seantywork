#ifndef _CONCURRENT_QUEUE_H_
#define _CONCURRENT_QUEUE_H_

#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <pthread.h>
#include <time.h>
#include <sys/queue.h>

#define TESTCASE 10000000
#define BUFFSIZE 2048

#define LOCK_SPIN 0
#define USE_SIGNAL 0


struct spinlock {
    int locked;

};
#define SPINLOCK_INIT { 0 };  


static inline bool _atomic_compare_exchange(int* ptr, int compare, int exchange) {

    return __atomic_compare_exchange_n(ptr, &compare, exchange,
            0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
}
static inline void _atomic_store(int* ptr, int value) {
    __atomic_store_n(ptr, value, __ATOMIC_SEQ_CST);
}


void spinlock_init(struct spinlock* spinlock, void* none) {
    _atomic_store(&spinlock->locked, 0);
}
void spinlock_lock(struct spinlock* spinlock) {
    while (!_atomic_compare_exchange(&spinlock->locked, 0, 1)) {
    }
}
void spinlock_unlock(struct spinlock* spinlock) {
    _atomic_store(&spinlock->locked, 0);
}



#if LOCK_SPIN
#define LOCK_T struct spinlock
#define COND_T struct spinlock
#define LOCK_INIT spinlock_init
#define LOCK_SIG_INIT spinlock_init
#define LOCK spinlock_lock
#define UNLOCK spinlock_unlock
#define LOCK_SIG_WAIT(sig, lock) \
                spinlock_unlock(lock); \
                continue; \

#define LOCK_SIG_SEND(sig) do{}while(0);
#else 
#define LOCK_T pthread_mutex_t
#define COND_T pthread_cond_t
#define LOCK_INIT pthread_mutex_init
#define LOCK_SIG_INIT pthread_cond_init
#define LOCK pthread_mutex_lock
#define UNLOCK pthread_mutex_unlock
#define LOCK_SIG_WAIT pthread_cond_wait
#if USE_SIGNAL
#define LOCK_SIG_SEND pthread_cond_signal
#else
#define LOCK_SIG_SEND pthread_cond_broadcast
#endif 
#endif



typedef struct array_node array_node;

struct array_node {
    uint32_t datalen;
    uint8_t in_use;
    uint8_t rsvc[3];
	void* data;
};

typedef struct array_bucket {
	uint32_t limit;
#if LOCK_SPIN
    struct spinlock lock;
    struct spinlock sig;
#else
	pthread_mutex_t lock;
	pthread_cond_t sig;
#endif
    array_node* arr;
    uint32_t head; 
	uint32_t tail;
} array_bucket;



typedef struct list_node list_node;

struct list_node {
    uint32_t datalen;
    uint8_t in_use;
    uint8_t rsvd[3];
	void* data;
	list_node* prev;
	list_node* next;
};

typedef struct list_bucket {
	uint32_t limit;
#if LOCK_SPIN
    struct spinlock lock;
    struct spinlock sig;
#else
	pthread_mutex_t lock;
	pthread_cond_t sig;
#endif
	list_node* qhead;
	list_node* qtail;
} list_bucket;



typedef struct sys_node sys_node;

struct sys_node {
    uint32_t datalen;
    uint8_t in_use;
    uint8_t rsvd[3];
    void* data;
    TAILQ_ENTRY(sys_node) entries;
};

typedef TAILQ_HEAD(sys_head, sys_node) sys_node_t;

typedef struct sys_bucket {
	uint32_t limit;
#if LOCK_SPIN
    struct spinlock lock;
    struct spinlock sig;
#else
	pthread_mutex_t lock;
	pthread_cond_t sig;
#endif
    uint32_t head; 
	uint32_t tail;
    sys_node* pool;
	sys_node_t* q;

} sys_bucket;


typedef struct testdata {
    uint32_t top;
    uint32_t bottom;
} testdata;


#define DECL_QUEUE(__q_t, __data_t) \
typedef struct __q_t##_node __q_t##_node; \
struct __q_t##_node { \
    uint32_t datalen; \
    uint8_t in_use; \
    uint8_t rsvd[3]; \
	__data_t* data; \
	__q_t##_node* prev; \
	__q_t##_node* next; \
}; \
typedef struct __q_t##_bucket { \
	uint32_t limit; \
	LOCK_T lock; \
	COND_T sig; \
	__q_t##_node* qhead; \
	__q_t##_node* qtail; \
} __q_t##_bucket; \
__q_t##_bucket* __q_t##_make(int max); \
void __q_t##_delete(__q_t##_bucket* q); \
void __q_t##_en(__q_t##_bucket* q, __data_t* data); \
void __q_t##_de(__q_t##_bucket* q, __data_t* data); \


#define DEF_QUEUE(__q_t, __data_t) \
__q_t##_bucket* __q_t##_make(int max){ \
    __q_t##_bucket* q = (__q_t##_bucket*)malloc(sizeof(__q_t##_bucket)); \
    memset(q, 0, sizeof(__q_t##_bucket)); \
    LOCK_INIT(&q->lock, NULL); \
    LOCK_SIG_INIT(&q->sig, NULL); \
    for(int i = 0; i < max; i++){ \
        __q_t##_node* n = (__q_t##_node*)malloc(sizeof(__q_t##_node)); \
        memset(n, 0, sizeof(__q_t##_node)); \
        n->data = malloc(sizeof(__data_t)); \
        n->datalen = sizeof(__data_t); \
        if(i == 0){ \
            q->qhead = n; \
            q->qtail = n; \
        } else { \
            q->qtail->next = n; \
            q->qtail = q->qtail->next; \
        } \
    } \
    q->qtail->next = q->qhead; \
    q->qtail = q->qhead; \
    q->limit = max; \
    return q; \
} \
void __q_t##_delete(__q_t##_bucket* q){ \
    if(q == NULL){ \
        return; \
    } \
    __q_t##_node* data = q->qhead; \
    LOCK(&q->lock); \
    for(int i = 0; i < q->limit; i++){ \
        __q_t##_node* tmp = data->next; \
        free(data->data); \
        free(data); \
        data = tmp; \
    } \
    UNLOCK(&q->lock); \
    free(q); \
} \
void __q_t##_en(__q_t##_bucket* q, __data_t* data){ \
    for(;;){ \
        LOCK(&q->lock); \
        if((q->qhead == q->qtail) && (q->qhead->in_use == 1)){ \
            LOCK_SIG_WAIT(&q->sig, &q->lock); \
        } \
        memcpy(q->qtail->data, data, q->qtail->datalen); \
        if((q->qhead == q->qtail) && (q->qhead->in_use != 1)){ \
            LOCK_SIG_SEND(&q->sig); \
        } \
        q->qtail->in_use = 1; \
        q->qtail = q->qtail->next; \
        UNLOCK(&q->lock); \
        break; \
    } \
} \
void __q_t##_de(__q_t##_bucket* q, __data_t* data){ \
    for(;;){ \
        LOCK(&q->lock); \
        if((q->qhead == q->qtail) && (q->qhead->in_use != 1)){ \
            LOCK_SIG_WAIT(&q->sig, &q->lock); \
        } \
        memcpy(data, q->qhead->data, q->qhead->datalen); \
        if((q->qhead == q->qtail) && (q->qhead->in_use == 1)){ \
            LOCK_SIG_SEND(&q->sig); \
        } \
        q->qhead->in_use = 0; \
        q->qhead = q->qhead->next; \
        UNLOCK(&q->lock); \
        break; \
    } \
} \

DECL_QUEUE(cc_queue, testdata)

#endif 