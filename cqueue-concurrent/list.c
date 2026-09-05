#include "concurrent_queue.h"



struct timespec THEN;
struct timespec NOW;


list_bucket* make_queue(uint32_t datalen, int max){
    list_bucket* q = (list_bucket*)malloc(sizeof(list_bucket));
    memset(q, 0, sizeof(list_bucket));
    LOCK_INIT(&q->lock, NULL);
    LOCK_SIG_INIT(&q->sig, NULL);
    for(int i = 0; i < max; i++){
        list_node* n = (list_node*)malloc(sizeof(list_node));
        memset(n, 0, sizeof(list_node));
        n->data = malloc(datalen);
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


void delete_queue(list_bucket* q){
    if(q == NULL){
        return;
    }
    list_node* data = q->qhead;
    LOCK(&q->lock);
    for(int i = 0; i < q->limit; i++){
        list_node* tmp = data->next;
        free(data->data);
        free(data);
        data = tmp;
    }
    UNLOCK(&q->lock);
    free(q);
}

inline void enqueue(list_bucket* q, void* data, uint32_t datalen){
    for(;;){
        LOCK(&q->lock);
        if((q->qhead == q->qtail) && (q->qhead->in_use == 1)){
            LOCK_SIG_WAIT(&q->sig, &q->lock);
        }
        memcpy(q->qtail->data, data, q->qtail->datalen);
        if((q->qhead == q->qtail) && (q->qhead->in_use != 1)){
            LOCK_SIG_SEND(&q->sig);
        }
        q->qtail->in_use = 1;
        q->qtail = q->qtail->next;
        UNLOCK(&q->lock);
        break;
    }

}

inline void dequeue(list_bucket* q, void* data, uint32_t datalen){

    for(;;){
        LOCK(&q->lock);
        if((q->qhead == q->qtail) && (q->qhead->in_use != 1)){
            LOCK_SIG_WAIT(&q->sig, &q->lock);
        }
        memcpy(data, q->qhead->data, q->qhead->datalen);
        if((q->qhead == q->qtail) && (q->qhead->in_use == 1)){
            LOCK_SIG_SEND(&q->sig);
        }
        q->qhead->in_use = 0;
        q->qhead = q->qhead->next;
        UNLOCK(&q->lock);
        break;
    }

}


void* do_enqueue(void* varg){
    testdata td;
    list_bucket* q = (list_bucket*)varg;
    clock_gettime(CLOCK_MONOTONIC_RAW, &THEN);
    for(int i = 0 ; i < TESTCASE; i++){
        td.top = i + 1;
        td.bottom =  i -1;
        enqueue(q, &td, sizeof(testdata));
    }
    pthread_exit(NULL);
}

int do_dequeue(list_bucket* q){
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
    return 0;
}

int main(){

    int lapsed_ms = 0;
    int result = 0;
    pthread_t tid;
    list_bucket* q = make_queue(sizeof(testdata),BUFFSIZE);
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