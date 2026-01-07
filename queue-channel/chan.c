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

#define USE_CORO 0

#define TESTCASE 1000000
#define BUFFSIZE 2048
struct timespec THEN;
struct timespec NOW;

#define LOCK_INIT pthread_mutex_init
#define LOCK_SIG_INIT pthread_cond_init
#define LOCK pthread_mutex_lock
#define LOCK_TRY pthread_mutex_trylock
#define UNLOCK pthread_mutex_unlock
#define LOCK_SIG_WAIT pthread_cond_wait
#define LOCK_SIG_SEND pthread_cond_signal



typedef struct node node;

struct node {
    uint8_t in_use;
	void* data;
	uint32_t datalen;
};

typedef struct bucket {
	uint32_t limit;
	pthread_mutex_t lock;
	pthread_cond_t sig;
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
    memset(q, 0, sizeof(bucket));
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
            if((hidx == tidx) && (q->arr[hidx].in_use == 1)){
                UNLOCK(&q->lock);
                continue;
            }
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
            if((hidx == tidx) && (q->arr[hidx].in_use != 1)){
                UNLOCK(&q->lock);
                continue;
            }
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

#if USE_CORO

int unlocked = 0;
#define DEFAULT_TASKS 4
#define DEFAULT_COTHREADS 4


typedef struct cotask {
    atomic_int lock;
    void (*func)(void* ret, void* data);
    void* ret;
    void* data;
} cotask;

typedef struct coman {
    pthread_mutex_t task_lock;
    int task_count;
    cotask* tasks;
    int thread_count;
    pthread_t* tids;
} coman;

void* _co_run(void* varg){
    coman* cm = (coman*)varg;
    while(1){
        for(int i = 0 ; i < cm->task_count; i++){
            if(atomic_compare_exchange_strong(&cm->tasks[i].lock, &unlocked, 1)){
                if(cm->tasks[i].func != NULL){
                    printf("fENTER: %p: i: %d: locked: %d\n", cm->tasks[i].func, i, cm->tasks[i].lock);
                    cm->tasks[i].func(cm->tasks[i].ret, cm->tasks[i].data);
                    cm->tasks[i].func = NULL;
                    cm->tasks[i].ret = NULL;
                    cm->tasks[i].data = NULL;
                }
                atomic_store(&cm->tasks[i].lock, 0);
            }
        }
    }
    pthread_exit(NULL);
}

coman* co_init(int task_count, int thread_count){
    coman* cm = (coman*)malloc(sizeof(coman));
    LOCK_INIT(&cm->task_lock, NULL);
    cm->task_count = task_count;
    cm->thread_count = thread_count;
    cm->tasks = (cotask*)malloc(sizeof(cotask) * cm->task_count);
    cm->tids = (pthread_t*)malloc(sizeof(pthread_t) * cm->thread_count);
    for(int i = 0; i < cm->task_count; i++){
        memset(&cm->tasks[i], 0, sizeof(cotask));
        atomic_store(&cm->tasks[i].lock, 0);
    }
    for(int i = 0; i < cm->thread_count; i++){
        pthread_create(&cm->tids[i], NULL, _co_run, (void*)cm);
    }
    return cm;
}

int co(coman* cm, void (*f)(void* ret, void* data), void* ret, void* data){
    int result = -1;
    for(int i = 0 ; i < cm->task_count; i++){
        if(atomic_compare_exchange_strong(&cm->tasks[i].lock, &unlocked, 1)){
            cm->tasks[i].func = f;
            cm->tasks[i].ret = ret;
            cm->tasks[i].data = data;
            atomic_store(&cm->tasks[i].lock, 0);
            result = i;
            break;
        }
    }
    return result;
}

void co_wait(void* ret, int (*cb)(void* ret)){
   struct timespec tim, tim2;
   while(!cb(ret)){
        tim.tv_sec = 0;
        tim.tv_nsec = 1000;
        nanosleep(&tim , &tim2);
        //sleep(1);
   }
}

void do_enqueue(void* ret, void* data){
    testdata td;
    bucket* q = (bucket*)data;
    clock_gettime(CLOCK_MONOTONIC_RAW, &THEN);
    for(int i = 0; i < TESTCASE; i++){
        td.top = i + 1;
        td.bottom =  i -1;
        printf("en: %d %d\n", td.top, td.bottom);
        enqueue(q, &td, sizeof(testdata));
    }
    *(int *)ret = 1;
    return;
}
int entry = 0;
void do_dequeue(void* ret,void* data){
    entry += 1;
    printf("ENTRY: %d\n", entry);
    testdata td;
    bucket* q = (bucket*)data;
    for(int i = 0; i < TESTCASE; i++){
        dequeue(q, &td, sizeof(testdata));
        printf("de: %d %d\n", td.top, td.bottom);
        if(td.top != (uint32_t)(i + 1)){
            *(int *)ret = -1;
            return;
        }
        if(td.bottom != (uint32_t)(i - 1)){
            *(int *)ret = -2;
            return;
        }
    }
    clock_gettime(CLOCK_MONOTONIC_RAW, &NOW);
    *(int *)ret = 1;
    return;
}

#else
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
#endif

int _check_cb(void* ret){
    int val = *(int *)ret;
    if(!val){
        return val;
    }
    return 0;
}

int main(){

    int lapsed_ms = 0;
    bucket* q = make_queue(sizeof(testdata),BUFFSIZE);
#if USE_CORO
    int* enret = (int*)malloc(sizeof(int));
    int* deret = (int*)malloc(sizeof(int));
    *enret = 0;
    *deret = 0;
    coman* cm = co_init(DEFAULT_TASKS, DEFAULT_COTHREADS);
    int result = co(cm, do_enqueue, (void*)enret, (void*)q);
    if(result < 0){
        printf("failed to create enqueue\n");
        goto exit;
    }
    result = co(cm, do_dequeue, (void*)deret, (void*)q);
    if(result < 0){
        printf("failed to create dequeue\n");
        goto exit;
    }
    co_wait((void*)enret, _check_cb);
    co_wait((void*)deret, _check_cb);
#else 
    void* result = NULL;
    thread_data thd;
    pthread_t tid_en;
    pthread_t tid_de;
    thd.b = q;
    thd.result = 0;
    pthread_create(&tid_en, NULL, do_enqueue, (void *)q);
    pthread_create(&tid_de, NULL, do_dequeue, (void *)&thd);
    pthread_join(tid_en, NULL);
    pthread_join(tid_de, NULL);
    if(thd.result < 0){
        printf("error: %d\n", thd.result);
        goto exit;
    }
#endif
    lapsed_ms = ((NOW.tv_sec - THEN.tv_sec) * 1000 + (NOW.tv_nsec - THEN.tv_nsec) / 1000000);
    printf("%d-entry, sized %d-byte, took %dms\n", TESTCASE, sizeof(testdata), lapsed_ms);
exit:
    delete_queue(q);
    return 0;

}