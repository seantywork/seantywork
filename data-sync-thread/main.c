#include <stdio.h>
#include <string.h>
#include <pthread.h>


int i = 2;

void* thread_func(void* p){

  printf("recevied as argument in starting routine: ");
  printf("%i\n", * (int*)p);


  pthread_exit(&i);
}

int main(void){

  pthread_t id;

  int j = 1;
  pthread_create(&id, NULL, thread_func, &j);
    
  int* ptr;

  pthread_join(id, (void**)&ptr);
  printf("recevied by main from thread: ");
  printf("%i\n", *ptr);
}
