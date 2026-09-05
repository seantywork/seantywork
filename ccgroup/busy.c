#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/random.h>

#define HOWMANY 100000
#define BUFFLEN 8192
int main(){
    uint8_t busybuff[BUFFLEN] = {0};
    printf("extremely busy process is about to start\n");
    for(int i = 0 ; i < HOWMANY; i++){
        getrandom(busybuff, BUFFLEN, 0);
        if(i % 10000){
            printf("running: %d\n", i);
        }
    }
    printf("extremely busy process is completed\n");
    return 0;
}