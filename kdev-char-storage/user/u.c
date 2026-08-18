#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#define DEV_NAME "./chr_store"

int open_file(FILE** f){
    *f = fopen(DEV_NAME, "r+");
    if(*f == NULL){
        return -1;
    }
    return 0;
}

int read_from_file(FILE* f){
    long fsize = 0;
    if(fseek(f, 0L, SEEK_END) == 0){
        fsize = ftell(f);
        if(fsize < 0){
            return -1;
        } 
        if(fseek(f, 0L, SEEK_SET) != 0){
            return -2;
        }
    } else {
        return -3;
    }
    if(fsize == 0){
        return 0;
    }
    char* buff = calloc(fsize, sizeof(char)); 
    int n = fread(buff, sizeof(char), fsize, f);
    printf("read: %d: %s\n", n, buff);
    free(buff);
    return n;
}

int write_to_file(FILE* f, char* msg){
    int arglen = strlen(msg);
    printf("target write size: %d\n", arglen);
    int n = fwrite(msg, sizeof(char), arglen, f);
    return n;
}

void close_file(FILE* f){
    fclose(f);
}

void* try_open_and_read(void* val){
    int* keepalive = (int*)val;
    int res;
    FILE* f = NULL;
    while(*keepalive){
        sleep(1);
        if((res = open_file(&f)) < 0){
            printf("thread: failed to open: %d\n", res);
            continue;
        }
        if((res = read_from_file(f)) < 0){
            printf("thread: failed to read: %d\n", res);
        }
        close_file(f);
        printf("thread: closed file\n");
    }
    if((res = open_file(&f)) < 0){
        printf("thread: failed to open: %d\n", res);
        pthread_exit(NULL);
    }
    if((res = read_from_file(f)) < 0){
        printf("thread: failed to read: %d\n", res);
    }
    close_file(f);
    printf("thread: closed file\n");
    *keepalive = 1;
    pthread_exit(NULL);
}

int main(int argc, char** argv){

    FILE* f = NULL;
    int keepalive = 1;
    pthread_t tid;
    pthread_create(&tid, NULL, try_open_and_read, (void*)&keepalive);
    printf("cmd: [w/q] \n");
    while(keepalive){
        int res;
        if((res = open_file(&f)) < 0){
            printf("main: failed to open file: %d\n", res);
            continue;
        }
        printf("main: file opened\n");
        char cmd;
        scanf(" %c", &cmd);
        do{
            if(cmd == 'w'){
                if(argc != 2){
                    printf("main: w option needs message argument from command line\n");
                    break;
                }
                if((res = write_to_file(f, argv[1])) < 0){
                    printf("main: failed to write to file: %d\n", res);
                }
            } else if (cmd == 'q') {
                printf("main: quit\n");
                keepalive = 0;
                close_file(f);
                goto out;
            } else {
                printf("invalid argument: %c\n", cmd);
            }
        }while(0);
        close_file(f);
        printf("main: file closed\n");
    }
out: 
    while(keepalive == 0){
        sleep(1);
    }
    return 0;
}