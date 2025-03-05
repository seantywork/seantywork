#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>



#define TLEN 10

void* thread_func(void* p){

    int* idx = (int*)p;

    int val = 1;

    if(*idx == 5) {

        printf("got 5\n");

        for(;;){

            val = val ^ 1;

        }
    }

    pthread_exit(NULL);
}

int main(void){

    pthread_t id[TLEN];


    for(int i = 0; i < TLEN; i++){

        int* j = (int*)malloc(sizeof(int));

        *j = i;

        pthread_create(&id[i], NULL, thread_func, j);

    }

    
    for(;;){

        sleep(1);

    }
}
