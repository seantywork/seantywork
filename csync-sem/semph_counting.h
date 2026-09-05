#ifndef _SEMPH_COUNTING_H_
#define _SEMPH_COUNTING_H_


#include <unistd.h>     
#include <sys/types.h>  
#include <errno.h>      
#include <stdio.h>      
#include <stdlib.h>     
#include <pthread.h>  
#include <string.h>    
#include <semaphore.h> 


#define SLOT_LEN 5
#define ITERATE 5

extern sem_t semph;
extern int produced;


extern int content_queue[SLOT_LEN];


void* producer(void* varg);

void* consumer(void* varg);



#endif 