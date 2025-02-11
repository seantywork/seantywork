
#include <pthread.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 
#include <unistd.h> 
  
pthread_t tid[2]; 
int counter = 0;   
int done = 0;

pthread_rwlock_t lock = PTHREAD_RWLOCK_INITIALIZER;

void* reader(void* arg) 
{ 
  
    printf("Job %d has started\n", counter); 
  
    for (; done == 0;) {

        pthread_rwlock_rdlock(&lock);

        printf("counter: %d\n", counter);

        pthread_rwlock_unlock(&lock); 
  
    }
  
    printf("Job %d has finished\n", counter); 
    
    return NULL; 
} 

void* writer(void* varg){

    for(int i = 0 ; i < 100000; i ++){

        pthread_rwlock_wrlock(&lock);

        counter += 1;

        pthread_rwlock_unlock(&lock);

    }

    pthread_rwlock_wrlock(&lock);

    done = 1;

    pthread_rwlock_unlock(&lock);

    return NULL;
}
  
int main(void) 
{ 
    int i = 0; 
    int error; 


    error = pthread_create(&(tid[i]), 
                        NULL, 
                        &reader, NULL); 
    if (error != 0) 
        printf("\nThread can't be created :[%s]", 
            strerror(error)); 

    error = pthread_create(&(tid[i]), 
                        NULL, 
                        &writer, NULL); 
    if (error != 0) 
        printf("\nThread can't be created :[%s]", 
            strerror(error)); 

  
    pthread_join(tid[0], NULL); 

 
  
    return 0; 
} 