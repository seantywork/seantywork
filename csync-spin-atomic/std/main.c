
#include <stdbool.h>
#include <stdatomic.h>
#include <pthread.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 
#include <unistd.h> 


void spinlock_init(atomic_int* lock) {
    *lock = 0;
}

void spinlock_lock(atomic_int* lock) {
    while (*lock == 1) {
    }
    *lock = 1;
}

void spinlock_unlock(atomic_int* lock) {
    *lock = 0;
}

pthread_t tid[2]; 

atomic_int lock = 0;

int counter = 0;

void* trythis(void* arg) 
{ 
    spinlock_lock(&lock); 
  
    unsigned long i = 0; 
    counter += 1; 
    printf("\n Job %d has started\n", counter); 
  
    for (i = 0; i < (0xFFFFFFFF); i++) 
        ; 
  
    printf("\n Job %d has finished\n", counter); 
  
    spinlock_unlock(&lock); 
  
    return NULL; 
} 
  
int main(void) 
{ 
    int i = 0; 
    int error; 
  
    spinlock_init(&lock);
  
    while (i < 2) { 
        error = pthread_create(&(tid[i]), 
                               NULL, 
                               &trythis, NULL); 
        if (error != 0) 
            printf("\nThread can't be created :[%s]", 
                   strerror(error)); 
        i++; 
    } 
  
    pthread_join(tid[0], NULL); 
    pthread_join(tid[1], NULL); 

  
    return 0; 
} 