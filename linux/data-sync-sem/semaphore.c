#include "semph_counting.h"



sem_t semph;

int produced = 0;

int content_queue[SLOT_LEN] = {0};

int pcomplete = 0;
int ccomplete = 0;

void* producer(void* varg){

    int epoch = 0;


    while(epoch < ITERATE){

        sem_wait(&semph);

        for(int i = 0; i < SLOT_LEN; i ++){

            content_queue[i] = i * epoch;
        }

        printf("produced\n");

        sem_post(&semph);

        sleep(1);

        epoch += 1;
    }

    pcomplete = 1;

}


void* consumer(void* varg){

    int epoch = 0;


    while(epoch < ITERATE){

        sem_wait(&semph);


        for(int i = 0 ; i < SLOT_LEN; i ++){

            printf("consumed: %d: %d\n", i, content_queue[i]);

            content_queue[i] = 0;

        }

        sem_post(&semph);

        sleep(1);

        epoch += 1;


    }


    ccomplete = 1;



}

int main(){


    pthread_t prod_th;
    pthread_t cons_th;
    
    sem_init(&semph, 0, 1);      
                                 
                            
    pthread_create(&prod_th, NULL, producer, NULL);
    pthread_create(&cons_th, NULL, consumer, NULL);


    while(pcomplete != 1 || ccomplete != 1){

        sleep(1);
    }


    sem_destroy(&semph); 
                  

    exit(0);
} 

