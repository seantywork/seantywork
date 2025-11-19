#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>

#include "kproc.h"

FILE* fp = NULL;
pthread_mutex_t mut;
int keepalive = 1;

void sig_hdl(int sig){
    printf("SIG: %d\n", sig);
    keepalive =0;
}

void* another_thread(void* varg){
    while(keepalive){
        pthread_mutex_lock(&mut);

        pthread_mutex_unlock(&mut);
        sleep(1);
    }
    pthread_exit(NULL);
}

int main(int argc, char** argv){
    pthread_t tid;
    int result = -1;
    char fbuf[1024] = {0};
    char* tbuf = NULL;
    size_t rlen = 0;
    int major = -1;
    fp = fopen("/proc/devices", "r");
    if(fp == NULL){
        printf("failed to open proc devices\n");
        return -1;
    }
    printf("devices:\n");
    while(fgets(fbuf, 1024, fp)){
        printf("%s", fbuf);
        if((tbuf = strstr(fbuf, "loop")) != NULL){
            tbuf -= 1;
            *tbuf = 0;
            tbuf -= 3;
            printf("target major: %s\n", tbuf);
            break;
        }
        memset(fbuf, 0, 1024 * sizeof(char));
    }
    fclose(fp);
    if(result < 0){
        printf("target not found\n");
        return -1;
    }
    result = -1;
    signal(SIGINT, sig_hdl);
    fp = fopen(DEVICE_NODNAME, "r+");
    if(fp == NULL){
        printf("failed to open\n");
        return -1;
    }
    pthread_mutex_init(&mut, NULL);
    result = pthread_create(&tid, NULL, another_thread, NULL);
    if(result < 0){
        printf("failed to create thread\n");
        return -1;
    }
    while(keepalive){
        pthread_mutex_lock(&mut);


        pthread_mutex_unlock(&mut);
        sleep(1);
    }
    fclose(fp);

    return 0;
}