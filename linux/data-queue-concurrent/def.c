#include "concurrent_queue.h"

DEF_QUEUE(cc_queue, testdata)

struct timespec THEN;
struct timespec NOW;

void* do_enqueue(void* varg){
    testdata td;
    cc_queue_bucket* q = (cc_queue_bucket*)varg;
    clock_gettime(CLOCK_MONOTONIC_RAW, &THEN);
    for(int i = 0 ; i < TESTCASE; i++){
        td.top = i + 1;
        td.bottom =  i -1;
        cc_queue_en(q, &td);
    }
    pthread_exit(NULL);
}

int do_dequeue(cc_queue_bucket* q){
    int counter = 0;
    testdata td;
    for(;counter < TESTCASE;){
        cc_queue_de(q, &td);
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
    cc_queue_bucket* q = cc_queue_make(BUFFSIZE);
    pthread_create(&tid, NULL, do_enqueue, (void *)q);
    if((result = do_dequeue(q)) < 0){
        printf("error: %d\n", result);
        goto exit;
    }
    lapsed_ms = ((NOW.tv_sec - THEN.tv_sec) * 1000 + (NOW.tv_nsec - THEN.tv_nsec) / 1000000);
    printf("%d-entry, sized %d-byte, took %dms\n", TESTCASE, sizeof(testdata), lapsed_ms);
exit:
    cc_queue_delete(q);
    return 0;

}