#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <pthread.h>
#include <time.h>


#define TESTCASE 100000000
struct timespec THEN;
struct timespec NOW;




#define LOCK_INIT pthread_mutex_init
#define LOCK_SIG_INIT pthread_cond_init
#define LOCK pthread_mutex_lock
#define UNLOCK pthread_mutex_unlock
#define LOCK_SIG_WAIT pthread_cond_wait
#define LOCK_SIG_SEND pthread_cond_signal


typedef struct node node;

struct node {
	void* data;
	uint32_t datalen;
	node* prev;
	node* next;
};

typedef struct bucket {
	uint32_t limit;
	uint32_t len;
	pthread_mutex_t lock;
	pthread_cond_t sig;
	node* qhead;
	node* qtail;
} bucket;


typedef struct testdata {
    uint32_t top;
    uint32_t bottom;
} testdata;


bucket* make_queue(int max){
    bucket* q = (bucket*)malloc(sizeof(bucket));
    memset(q, 0, sizeof(bucket));
    LOCK_INIT(&q->lock, NULL);
    LOCK_SIG_INIT(&q->sig, NULL);
    q->limit = max;
    return q;
}


void delete_queue(bucket* q){
    if(q == NULL){
        return;
    }
    node* data = q->qhead;
    LOCK(&q->lock);
    for(;;){
        if(data == NULL){
            break;
        }
        node* tmp = data->next;
        free(data->data);
        free(data);
        data = tmp;
    }
    UNLOCK(&q->lock);
    free(q);
}

inline void enqueue(bucket* q, void* data, uint32_t datalen){
    for(;;){
        LOCK(&q->lock);
        if(q->len == q->limit){
            LOCK_SIG_WAIT(&q->sig, &q->lock);
        }
        node* newd = (node*)malloc(sizeof(node));
        //memset(newd, 0, sizeof(node));
        newd->data = malloc(datalen);
        newd->datalen = datalen;
        memcpy(newd->data, data, newd->datalen);
        newd->prev = NULL;
        newd->next = q->qhead;
        if(q->len == 0){
            q->qtail = newd;
            LOCK_SIG_SEND(&q->sig);
        }else {
            q->qhead->prev = newd;
        }
        q->qhead = newd;
        q->len += 1;
        UNLOCK(&q->lock);
        break;
    }

}

inline void dequeue(bucket* q, void* data, uint32_t datalen){

    for(;;){
        LOCK(&q->lock);
        if(q->len == 0){
            LOCK_SIG_WAIT(&q->sig, &q->lock);
        }
        node* d = q->qtail;
        memcpy(data, d->data, datalen);
        q->qtail = d->prev;
        free(d->data);
        free(d);
        if(q->len == 1){
            q->qhead = NULL;
            q->qtail = NULL;
        }else {
            q->qtail->next = NULL;
            if(q->len == q->limit){
                LOCK_SIG_SEND(&q->sig);
            }
        }
        q->len -= 1;
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

int do_dequeue(bucket* q){
    int counter = 0;
    testdata td;
    for(;counter < TESTCASE;){
        dequeue(q, &td, sizeof(testdata));
        if(td.top != (uint32_t)(counter + 1)){
            return -1;
        }
        if(td.bottom != (uint32_t)(counter - 1)){
            return -2;
        }
        counter += 1;
    }
    clock_gettime(CLOCK_MONOTONIC_RAW, &NOW);
}

int main(){

    int lapsed_ms = 0;
    int result = 0;
    pthread_t tid;
    bucket* q = make_queue(TESTCASE);
    pthread_create(&tid, NULL, do_enqueue, (void *)q);
    if((result = do_dequeue(q)) < 0){
        printf("error: %d\n", result);
        goto exit;
    }
    lapsed_ms = ((NOW.tv_sec - THEN.tv_sec) * 1000 + (NOW.tv_nsec - THEN.tv_nsec) / 1000000);
    printf("%d-entry, sized %d-byte, took %dms\n", TESTCASE, sizeof(testdata), lapsed_ms);
exit:
    delete_queue(q);
    return 0;

}