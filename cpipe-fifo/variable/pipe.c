#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <pthread.h>

int fd[2];



void* writer(){

    
    char wbuff[128] = {0};

    sleep(3);

    for(int i = 0 ; i < 100; i++){


        sprintf(wbuff, "hello! for %d", i);

        write(fd[1], wbuff, 128);

        memset(wbuff, 0 , 128);



    }


}

void* reader(){


    int count = 0;

    char rbuff[128] = {0};

    printf("read ready\n");

    while(count < 100){


        int n = read(fd[0], rbuff, 128);

        printf("read: %s: %d\n", rbuff, n);

        memset(rbuff, 0, 128);

        count += 1;

    }

}





int main(){

    pthread_t w;
    pthread_t r;

    pipe(fd);


    pthread_create(&w, NULL, writer, NULL);

    pthread_create(&r, NULL, reader, NULL);


    pthread_join(r, NULL);


    return 0;
}