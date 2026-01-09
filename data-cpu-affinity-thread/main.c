#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>


void* thread_func(void* varg){

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);

    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);

    for(int i = 0  ; i < 10; i ++){


        sleep(1);

    }    



    return (void*)EXIT_SUCCESS;
}

int main(){


    pthread_t tid;

    int result = pthread_create(&tid, NULL, thread_func, NULL);

    if(result < 0){

        printf("failed to start thread: %d\n", result);

        return -1;

    }

    void* retnum = NULL;

    pthread_join(tid, &retnum);


    return 0;
}