#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/random.h>

#define HOWMANY 1000000
#define BUFFLEN 8192
#define PINCPU 1

void* thread_func_pinned(void* varg){
    uint8_t buff[BUFFLEN] = {0};
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(PINCPU, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    for(int i = 0  ; i < HOWMANY; i ++){
        getrandom(buff, BUFFLEN, 0);
    }    
    return (void*)EXIT_SUCCESS;
}

void* thread_func_not_pinned(void* varg){
    uint8_t buff[BUFFLEN] = {0};
    for(int i = 0  ; i < HOWMANY; i ++){
        getrandom(buff, BUFFLEN, 0);
    }    
    return (void*)EXIT_SUCCESS;
}

int main(){
    pthread_t tid;
    pthread_t tid2;
    int result = pthread_create(&tid, NULL, thread_func_not_pinned, NULL);
    if(result < 0){
        printf("failed to start unthread: %d\n", result);
        return -1;
    }
    result = pthread_create(&tid2, NULL, thread_func_pinned, NULL);
    if(result < 0){
        printf("failed to start pinned thread\n");
    }
    void* retnum = NULL;
    pthread_join(tid, &retnum);
    pthread_join(tid2, &retnum);
    return 0;
}