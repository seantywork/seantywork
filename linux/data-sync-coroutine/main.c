#include <stdio.h>
#include <assert.h>
#include <unistd.h>

#include "coroutine.h"

#define VERSION 2



#if VERSION == 0

int hello_world() {    
    scrBegin;
    puts("Hello");
    scrReturn(1);
    puts("World");
    scrReturn(2);
    scrFinish(-1);
}


int main(){
    assert(hello_world() == 1);     // Verifying return value
    printf("main hello\n");
    assert(hello_world() == 2);     // Verifying return value
    printf("main world\n");
    assert(hello_world() == -1);    // Invalid call

    return EXIT_SUCCESS;
}



#elif VERSION == 1

int hello_world(ccrContParam) {   

    ccrBeginContext;
    int i;
    ccrEndContext(z);

    ccrBegin(z);
    puts("Hello");
    z->i = 1;
    ccrReturn(z->i);
    puts("World");
    z->i += 1;
    ccrReturn(z->i);
    ccrFinish(0);
}


int main(){

    ccrContext z = 0;

    do {

        printf("got number %d\n", hello_world(&z));

    } while(z);

    return EXIT_SUCCESS;
}



#else


int hello_world(coro_t *coro) {    
    puts("Hello");
    coro_yield(coro, 1);    // Suspension point that returns the value `1`
    puts("World");
    return 2;
}


int main() {
    coro_t *coro = coro_new(hello_world);
    assert(coro_resume(coro) == 1);     // Verifying return value
    assert(coro_resume(coro) == 2);     // Verifying return value
    assert(coro_resume(coro) == -1);    // Invalid call
    coro_free(coro);
    return EXIT_SUCCESS;
}

#endif 

