#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEV_NAME "./chr_store"

void print_help(){
    printf("r $number: reads $number of characters from the beginning\n");
    printf("w \"$message\": write $message to the file\n");
}

int main(int argc, char** argv){

    FILE* f = NULL;
    int number = 0;
    char* buff = NULL;
    if(argc != 3){
        print_help();
        return -1;
    }
    f = fopen(DEV_NAME, "r+");
    if(f == NULL){
        printf("failed to open file: %s\n", DEV_NAME);
        return -1;
    }
    if(strcmp(argv[1], "r") == 0){
        long fsize = 0;
        sscanf(argv[2], "%d", &number);
        if(fseek(f, 0L, SEEK_END) == 0){
            fsize = ftell(f);
            if(fsize < 0){
                printf("failed to seek size\n");
                goto out;
            } 
            if(fseek(f, 0L, SEEK_SET) != 0){
                printf("failed to reset pos\n");
                goto out;
            }
        } else {
            printf("failed to seek eof\n");
            goto out;
        }
        if(fsize == 0){
            printf("nothing to read\n");
            return 0;
        }
        printf("current chr_storage size: %ld\n", fsize);
        buff = calloc(fsize, sizeof(char)); 
        int n = fread(buff, sizeof(char), number, f);
        printf("read: %d: %s\n", n, buff);
        free(buff);
    } else if(strcmp(argv[1], "w") == 0){
        int arglen = strlen(argv[2]);
        int n = fwrite(argv[2], sizeof(char), arglen, f);
        printf("write: %d\n", n);
    } else {
        printf("invalid argument: %s\n", argv[1]);
        print_help();
        return -1;
    }
out: 
    fclose(f);

    return 0;
}