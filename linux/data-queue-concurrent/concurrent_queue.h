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
#define LOCK_INIT spinlock_init
#define LOCK_SIG_INIT spinlock_init
#define LOCK spinlock_lock
#define UNLOCK spinlock_unlock
#define LOCK_SIG_WAIT(sig, lock) \
                spinlock_unlock(lock); \
                continue; \

#define LOCK_SIG_SEND(sig) do{}while(0);
#else 
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


typedef struct testdata {
    uint32_t top;
    uint32_t bottom;
} testdata;


#endif 