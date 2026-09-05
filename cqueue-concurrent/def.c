#include "concurrent_queue.h"

DEF_QUEUE(cc_queue, testdata)

#define TEST_THREADS 16
pthread_t en_tids[TEST_THREADS];
pthread_t de_tids[TEST_THREADS];

int test_value = 0;

struct timespec THEN;
struct timespec NOW;



static inline int atomic_add_fetch(int* ptr, int d) {
    return __atomic_add_fetch(ptr, d, __ATOMIC_SEQ_CST);
}


void* do_enqueue(void* varg){
    testdata td;
    cc_queue_bucket* q = (cc_queue_bucket*)varg;
    for(int i = 0 ; i < TESTCASE; i++){
        td.top = i + 1;
        td.bottom =  i + 1;
        atomic_add_fetch(&test_value, td.top + td.bottom);
        cc_queue_en(q, &td);
    }
    pthread_exit(NULL);
}

void* do_dequeue(void* varg){
    int counter = 0;
    testdata td;
    cc_queue_bucket* q = (cc_queue_bucket*)varg;
    for(;counter < TESTCASE;){
        cc_queue_de(q, &td);
        atomic_add_fetch(&test_value, (td.top + td.bottom) * -1);
        counter += 1;
    }
    pthread_exit(NULL);
}

int main(){

    int lapsed_ms = 0;
    int result = 0;
    cc_queue_bucket* q = cc_queue_make(BUFFSIZE);
    clock_gettime(CLOCK_MONOTONIC_RAW, &THEN);
    for(int i = 0; i < TEST_THREADS; i++){
        pthread_create(&en_tids[i], NULL, do_enqueue, (void *)q);
        pthread_create(&de_tids[i], NULL, do_dequeue, (void *)q);
    }
    printf("all threads created: %d\n", TEST_THREADS);
    for(int i = 0; i < TEST_THREADS; i++){
        pthread_join(en_tids[i], NULL);
    }
    printf("enqueue threads all done\n");
    for(int i = 0; i < TEST_THREADS; i++){
        pthread_join(de_tids[i], NULL);
    }
    printf("dequeue threads all done\n");
    clock_gettime(CLOCK_MONOTONIC_RAW, &NOW);
    lapsed_ms = ((NOW.tv_sec - THEN.tv_sec) * 1000 + (NOW.tv_nsec - THEN.tv_nsec) / 1000000);
    printf("%d-entry, sized %d-byte, took %dms\n", TESTCASE, sizeof(testdata), lapsed_ms);
    printf("result: %d (should be 0)\n", test_value);
exit:
    cc_queue_delete(q);
    return 0;

}