#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include "kproc.h"

FILE* fp = NULL;
pthread_mutex_t mut;
int keepalive = 1;

void sig_hdl(int sig){
    printf("SIG: %d\n", sig);
    keepalive =0;
}

void* another_thread(void* varg){
    char fbuf[1024] = {0};
    int n = 0;
    while(keepalive){
        pthread_mutex_lock(&mut);
        n = fread(fbuf, sizeof(char), 1024, fp);
        printf("thread: %s\n", fbuf);
        memset(fbuf, 0, 1024);
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
        if((tbuf = strstr(fbuf, DEVICE_NAME)) != NULL){
            tbuf -= 1;
            *tbuf = 0;
            tbuf -= 3;
            sscanf(tbuf, "%d", &major);
            printf("target major: %d\n", major);
            break;
        }
        memset(fbuf, 0, 1024 * sizeof(char));
    }
    fclose(fp);
    if(major < 0){
        printf("target not found\n");
        return -1;
    }
    result = mknodat(AT_FDCWD, DEVICE_NODNAME, 0666 | S_IFCHR, makedev(major, 0));
    if(result != 0){
        printf("mknod failed\n");
        return -1;
    }
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
    memset(fbuf, 0, 1024);
    while(keepalive){
        pthread_mutex_lock(&mut);
        int n = fread(fbuf, sizeof(char), 1024, fp);
        printf("main: %s\n", fbuf);
        memset(fbuf, 0, 1024);
        pthread_mutex_unlock(&mut);
        sleep(1);
    }
    remove(DEVICE_NODNAME);
    fclose(fp);

    return 0;
}