#include "concurrent_queue.h"


struct timespec THEN;
struct timespec NOW;





array_bucket* make_queue(uint32_t datalen, int max){
    array_bucket* q = (array_bucket*)malloc(sizeof(array_bucket));
    memset(q, 0, sizeof(array_bucket));
    LOCK_INIT(&q->lock, NULL);
    LOCK_SIG_INIT(&q->sig, NULL);
    array_node* n = (array_node*)malloc(sizeof(array_node) * max);
    for(int i = 0 ; i < max; i++){
        memset(&(n[i]), 0, sizeof(array_node));
        n[i].data = malloc(datalen);
        n[i].datalen = datalen;
    }
    q->limit = max;
    q->arr = n;
    return q;
}

void delete_queue(array_bucket* q){
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

inline void enqueue(array_bucket* q, void* data, uint32_t datalen){
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

inline void dequeue(array_bucket* q, void* data, uint32_t datalen){
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
    array_bucket* q = (array_bucket*)varg;
    clock_gettime(CLOCK_MONOTONIC_RAW, &THEN);
    for(int i = 0 ; i < TESTCASE; i++){
        td.top = i + 1;
        td.bottom =  i -1;
        enqueue(q, &td, sizeof(testdata));
    }
    pthread_exit(NULL);
}

int do_dequeue(array_bucket* q){
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
    array_bucket* q = make_queue(sizeof(testdata),BUFFSIZE);
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