#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>
#include <pthread.h>
#include <time.h>

#define USE_SPIN 0

#define TESTCASE 1000000
#define BUFFSIZE 2048
struct timespec THEN;
struct timespec NOW;

static inline bool atomic_compare_exchange(int* ptr, int compare, int exchange) {
    return __atomic_compare_exchange_n(ptr, &compare, exchange,
            0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
}

static inline void atomic_store(int* ptr, int value) {
    __atomic_store_n(ptr, value, __ATOMIC_SEQ_CST);
}

static inline int atomic_add_fetch(int* ptr, int d) {
    return __atomic_add_fetch(ptr, d, __ATOMIC_SEQ_CST);
}

struct spinlock {
    int locked;
};

struct spincond {
    int sig;
};

void spinlock_init(struct spinlock* spinlock, void* none) {
    atomic_store(&spinlock->locked, 0);
}

void spinlock_cond_init(struct spincond* spincond, void* none) {
    atomic_store(&spincond->sig, 0);
}


void spinlock_lock(struct spinlock* spinlock) {
    while (!atomic_compare_exchange(&spinlock->locked, 0, 1)) {
    }
}

void spinlock_unlock(struct spinlock* spinlock) {
    atomic_store(&spinlock->locked, 0);
}


#if USE_SPIN
#define LOCK_INIT spinlock_init
#define LOCK_SIG_INIT spinlock_cond_init
#define LOCK spinlock_lock
#define UNLOCK spinlock_unlock
#define LOCK_SIG_WAIT(sig, lock)    UNLOCK(lock); \
                                    continue;
#define LOCK_SIG_SEND(sig) do{} while(0);
#else
#define LOCK_INIT pthread_mutex_init
#define LOCK_SIG_INIT pthread_cond_init
#define LOCK pthread_mutex_lock
#define UNLOCK pthread_mutex_unlock
#define LOCK_SIG_WAIT pthread_cond_wait
#define LOCK_SIG_SEND pthread_cond_signal
#endif


typedef struct node node;

struct node {
    uint8_t in_use;
	void* data;
	uint32_t datalen;
};

typedef struct bucket {
	uint32_t limit;
#if USE_SPIN
    struct spinlock lock;
    struct spincond sig;
#else 
	pthread_mutex_t lock;
	pthread_cond_t sig;
#endif
    node* arr;
    uint32_t head; 
	uint32_t tail;
} bucket;


typedef struct thread_data{
    bucket* b;
    int result;
} thread_data;

typedef struct testdata {
    uint32_t top;
    uint32_t bottom;
} testdata;


bucket* make_queue(uint32_t datalen, int max){
    bucket* q = (bucket*)malloc(sizeof(bucket));
    //memset(q, 0, sizeof(bucket));
    LOCK_INIT(&q->lock, NULL);
    LOCK_SIG_INIT(&q->sig, NULL);
    node* n = (node*)malloc(sizeof(node) * max);
    for(int i = 0 ; i < max; i++){
        memset(&(n[i]), 0, sizeof(node));
        n[i].data = malloc(datalen);
        n[i].datalen = datalen;
    }
    q->limit = max;
    q->arr = n;
    return q;
}

void delete_queue(bucket* q){
    if(q == NULL){
        return;
    }
    LOCK(&q->lock);
    for(int i = 0; i < q->limit; i++){
        free(q->arr[i].data);
    }
    free(q->arr);
    UNLOCK(&q->lock);
    free(q);
}

void enqueue(bucket* q, void* data, uint32_t datalen){
    for(;;){
        LOCK(&q->lock);
        uint32_t hidx = q->head % q->limit;
        uint32_t tidx = q->tail % q->limit;
        if((hidx == tidx) && (q->arr[hidx].in_use == 1)){
            LOCK_SIG_WAIT(&q->sig, &q->lock);
        }
        memcpy(q->arr[tidx].data, data, q->arr[tidx].datalen);
        if((hidx == tidx) && (q->arr[hidx].in_use != 1)){
            LOCK_SIG_SEND(&q->sig);
        }
        q->arr[tidx].in_use = 1;
        q->tail += 1;
        UNLOCK(&q->lock);
        break;
    }
}

void dequeue(bucket* q, void* data, uint32_t datalen){
    for(;;){
        LOCK(&q->lock);
        uint32_t hidx = q->head % q->limit;
        uint32_t tidx = q->tail % q->limit;
        if((hidx == tidx) && (q->arr[hidx].in_use != 1)){
            LOCK_SIG_WAIT(&q->sig, &q->lock);
        }
        memcpy(data, q->arr[hidx].data, q->arr[hidx].datalen);
        if((hidx == tidx) && (q->arr[hidx].in_use == 1)){
            LOCK_SIG_SEND(&q->sig);
        }
        q->arr[hidx].in_use = 0;
        q->head += 1;
        UNLOCK(&q->lock);
        break;
    }
}

void* do_enqueue(void* varg){
    testdata td;
    bucket* q = (bucket*)varg;
    clock_gettime(CLOCK_MONOTONIC_RAW, &THEN);
    for(int i = 0 ; i < TESTCASE; i++){
        td.top = i + 1;
        td.bottom =  i -1;
        enqueue(q, &td, sizeof(testdata));
    }
    pthread_exit(NULL);
}
void* do_dequeue(void* varg){
    int counter = 0;
    testdata td;
    thread_data* thd = (thread_data*)varg;
    bucket* q = thd->b;
    for(;counter < TESTCASE;){
        dequeue(q, &td, sizeof(testdata));
        if(td.top != (uint32_t)(counter + 1)){
            thd->result = -1;
            pthread_exit(NULL);
        }
        if(td.bottom != (uint32_t)(counter - 1)){
            thd->result = -2;
            pthread_exit(NULL);
        }
        counter += 1;
    }
    clock_gettime(CLOCK_MONOTONIC_RAW, &NOW);
    pthread_exit(NULL);
}



int main(){

    int lapsed_ms = 0;
    bucket* q = make_queue(sizeof(testdata),BUFFSIZE);

    void* result = NULL;
    thread_data thd;
    pthread_t tid_en;
    pthread_t tid_de;
    thd.b = q;
    thd.result = 0;
    pthread_create(&tid_de, NULL, do_dequeue, (void *)&thd);
    pthread_create(&tid_en, NULL, do_enqueue, (void *)q);
    pthread_join(tid_en, NULL);
    pthread_join(tid_de, NULL);
    if(thd.result < 0){
        printf("error: %d\n", thd.result);
        goto exit;
    }

    lapsed_ms = ((NOW.tv_sec - THEN.tv_sec) * 1000 + (NOW.tv_nsec - THEN.tv_nsec) / 1000000);
    printf("%d-entry, sized %d-byte, took %dms\n", TESTCASE, sizeof(testdata), lapsed_ms);
exit:
    delete_queue(q);
    return 0;

}