
#include <stdbool.h>
#include <pthread.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 
#include <unistd.h> 

#define SPINLOCK_INIT { 0 };  

static inline bool atomic_compare_exchange(int* ptr, int compare, int exchange) {
    return __atomic_compare_exchange_n(ptr, &compare, exchange,
            0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
}

static inline void atomic_store(int* ptr, int value) {
    __atomic_store_n(ptr, value, __ATOMIC_SEQ_CST);
}

static inline int atomic_add_fetch(int* ptr, int d) {
    return __atomic_add_fetch(ptr, d, __ATOMIC_SEQ_CST);
}


struct spinlock {
    int locked;
};

void spinlock_init(struct spinlock* spinlock) {
    atomic_store(&spinlock->locked, 0);
}

void spinlock_lock(struct spinlock* spinlock) {
    while (!atomic_compare_exchange(&spinlock->locked, 0, 1)) {
    }
}

void spinlock_unlock(struct spinlock* spinlock) {
    atomic_store(&spinlock->locked, 0);
}

pthread_t tid[2]; 

struct spinlock lock;

int counter = 0;

void* trythis(void* arg) { 
    printf("job started\n"); 
    for (int i = 0; i < 100000000; i++){
        spinlock_lock(&lock);
        counter += 1;
        spinlock_unlock(&lock);
    }
  
    return NULL; 
} 
  
int main(void) { 
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
    printf("counter: %d\n", counter);
  
    return 0; 
} 