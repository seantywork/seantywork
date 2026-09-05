#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>



#define TLEN 10

void* thread_func(void* p){

    int* idx = (int*)p;

    int val = 1;

    struct timespec request, remaing; 

    request.tv_sec = 0;
    request.tv_nsec = 500000000L;

    if(*idx == 5) {

        for(;;){

            val = val ^ 1;

        }

    } else {

        for(;;){

            if(nanosleep(&request , &remaing) < 0){

                printf("error sleep at: %d\n", *idx);

                break;

            }

            val = val ^ 1;

        }

    }

    pthread_exit(NULL);
}

void* thread_func_segv(void* p){

    int* idx = (int*)p;

    int* segv = (int*)p;

    int val = 1;

    struct timespec request, remaing; 

    request.tv_sec = 0;
    request.tv_nsec = 500000000L;

    if(*idx == 5) {

        sleep(5);

        segv = NULL;

        val = *segv;

        printf("%d\n", val);

    } else {

        for(;;){

            if(nanosleep(&request , &remaing) < 0){

                printf("error sleep at: %d\n", *idx);

                break;

            }

            val = val ^ 1;

        }

    }

    pthread_exit(NULL);
}


int main(int argc, char **argv){

    pthread_t id[TLEN];

    if(argc != 2){

        printf("feed case\n");

        return -1;
    }

    if(strcmp(argv[1], "1") == 0){

        for(int i = 0; i < TLEN; i++){
    
            int* j = (int*)malloc(sizeof(int));
    
            *j = i;
    
            pthread_create(&id[i], NULL, thread_func, j);
    
        }
    
        
        for(;;){
    
            sleep(1);
    
        }

    } else if (strcmp(argv[1], "2") == 0){

        for(int i = 0; i < TLEN; i++){
    
            int* j = (int*)malloc(sizeof(int));
    
            *j = i;
    
            pthread_create(&id[i], NULL, thread_func_segv, j);
    
        }
    
        
        for(;;){
    
            sleep(1);
    
        }

    }


}
