#include "concurrent_queue.h"


struct timespec THEN;
struct timespec NOW;


sys_bucket* make_queue(uint32_t datalen, int max){
    sys_bucket* q = (sys_bucket*)malloc(sizeof(sys_bucket));
    memset(q, 0, sizeof(sys_bucket));
    LOCK_INIT(&q->lock, NULL);
    LOCK_SIG_INIT(&q->sig, NULL);
    q->q = (sys_node_t*)malloc(sizeof(sys_node_t));
    TAILQ_INIT(q->q);
    q->pool = (sys_node*)malloc(sizeof(sys_node) * max);
    for(int i = 0 ; i < max; i++){
        memset(&(q->pool[i]), 0, sizeof(sys_node));
        q->pool[i].datalen = datalen;
        q->pool[i].data = malloc(datalen);
    }
    q->limit = max;
    return q;
}

void delete_queue(sys_bucket* q){
    if(q == NULL){
        return;
    }
    LOCK(&q->lock);
    // TODO
    //  free 
    UNLOCK(&q->lock);
    free(q);
}

inline void enqueue(sys_bucket* q, void* data, uint32_t datalen){
    for(;;){
        LOCK(&q->lock);
        uint32_t hidx = q->head % q->limit;
        uint32_t tidx = q->tail % q->limit;
        if((hidx == tidx) && (q->pool[hidx].in_use == 1)){
            LOCK_SIG_WAIT(&q->sig, &q->lock);
        }
        struct sys_node* n = &(q->pool[tidx]);
        memcpy(n->data, data, n->datalen);
        TAILQ_INSERT_TAIL(q->q, n, entries);
        if((hidx == tidx) && (q->pool[hidx].in_use != 1)){
            LOCK_SIG_SEND(&q->sig);
        }
        q->pool[tidx].in_use = 1;
        q->tail += 1;
        UNLOCK(&q->lock);
        break;
    }
}

inline void dequeue(sys_bucket* q, void* data, uint32_t datalen){
    for(;;){
        LOCK(&q->lock);
        uint32_t hidx = q->head % q->limit;
        uint32_t tidx = q->tail % q->limit;
        if((hidx == tidx) && (q->pool[hidx].in_use != 1)){
            LOCK_SIG_WAIT(&q->sig, &q->lock);
        }
        struct sys_node* n = TAILQ_FIRST(q->q);
        memcpy(data, n->data, n->datalen);
        TAILQ_REMOVE(q->q, n, entries);
        if((hidx == tidx) && (q->pool[hidx].in_use == 1)){
            LOCK_SIG_SEND(&q->sig);
        }
        q->pool[hidx].in_use = 0;
        q->head += 1;
        UNLOCK(&q->lock);
        break;
    }
}


void* do_enqueue(void* varg){
    testdata td;
    sys_bucket* q = (sys_bucket*)varg;
    clock_gettime(CLOCK_MONOTONIC_RAW, &THEN);
    for(int i = 0 ; i < TESTCASE; i++){
        td.top = i + 1;
        td.bottom =  i -1;
        enqueue(q, &td, sizeof(testdata));
    }
    pthread_exit(NULL);
}

int do_dequeue(sys_bucket* q){
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
    sys_bucket* q = make_queue(sizeof(testdata), BUFFSIZE);
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