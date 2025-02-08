#include "server_ep.h"

void handle_conn(){


    while(TRUE){

        struct sockaddr in_addr;
        socklen_t in_len;
        int infd;

        in_len = sizeof(in_addr);
   
        infd = accept(SOCKFD, &in_addr, &in_len);

        if(infd == -1){

            if(
                (errno == EAGAIN) ||
                (errno == EWOULDBLOCK)
            ){
                printf("all incoming connections handled\n");
                break;

            } else{
                printf("errbo: %d\n", errno);
                printf("error handling incoming connection\n");
                break;
            }
        }

        if(make_socket_non_blocking(infd) < 0){
            printf("failed new conn non block\n");
            exit(EXIT_FAILURE);
        }

        EVENT.data.fd = infd;
        EVENT.events = EPOLLIN | EPOLLET;

        if (epoll_ctl(EPLFD, EPOLL_CTL_ADD, infd, &EVENT) < 0){

            printf("handle epoll add failed\n");
            exit(EXIT_FAILURE);

        }  else {

            printf("handle epoll add success\n");

        }



    }


}


void handle_client(int i){

    int done = 0;


    int valread = 0;
    char buff[MAX_BUFF] = {0}; 
    struct sockaddr_in peeraddr;
    socklen_t peerlen;

    peerlen = sizeof(peeraddr);

    while(valread != MAX_BUFF){

        int n = 0;

        n = read(CLIENT_SOCKET[i].data.fd, buff + valread, MAX_BUFF - valread);

        if(n == -1){

            if(errno != EAGAIN){
                printf("handle read error\n");
                
            }

            done = 1;      


        } else if (n == 0){

            getpeername(CLIENT_SOCKET[i].data.fd, (SA*)&peeraddr, &peerlen);
            printf("client disconnected: ip=%s, port=%d\n",
                inet_ntoa(peeraddr.sin_addr),
                ntohs(peeraddr.sin_port)
            );

            done = 1;

        }

        valread += n;    

    }

    if (done){

        close(CLIENT_SOCKET[i].data.fd);
        printf("closed sock\n");
        return;
    }

    to_worker(i, CLIENT_SOCKET[i].data.fd, (uint8_t*)buff);


}


void to_worker(int id, int fd, uint8_t* data){

    pthread_mutex_lock(&APOOL[id].lock);


    APOOL[id].fd = fd;
    APOOL[id].data = data;

    pthread_cond_signal(&APOOL[id].cond);

    pthread_mutex_unlock(&APOOL[id].lock);
}

void* worker(void *varg){

    int id = *(int*)varg;

    int wfd;

    uint8_t *wdata;

    while(1){

        pthread_mutex_lock(&APOOL[id].lock);

        pthread_cond_wait(&APOOL[id].cond, &APOOL[id].lock);

        wfd = APOOL[id].fd;

        wdata = (uint8_t*)malloc(MAX_BUFF * sizeof(uint8_t));

        memset(wdata, APOOL[id].data, MAX_BUFF * sizeof(uint8_t));

        memcpy(wdata, APOOL[id].data, MAX_BUFF * sizeof(uint8_t));

        pthread_mutex_unlock(&APOOL[id].lock);
        

        printf("worker: %d: received: %s\n", id, wdata);

        to_writer(id, wfd, wdata);


    }

}

void to_writer(int id, int fd, uint8_t* data){


    pthread_mutex_lock(&AWPOOL[id].lock);

    AWPOOL[id].fd = fd; 

    AWPOOL[id].data = data;

    pthread_cond_signal(&AWPOOL[id].cond);

    pthread_mutex_unlock(&AWPOOL[id].lock);   
}


void* writer(void *varg){

    int id = *(int*)varg;

    int wfd;

    uint8_t *wdata;

    for (;;){

        pthread_mutex_lock(&AWPOOL[id].lock);

        pthread_cond_wait(&AWPOOL[id].cond, &AWPOOL[id].lock);

        wfd = AWPOOL[id].fd;

        wdata = (uint8_t*)malloc(MAX_BUFF * sizeof(uint8_t));

        memset(wdata, AWPOOL[id].data, MAX_BUFF * sizeof(uint8_t));

        memcpy(wdata, AWPOOL[id].data, MAX_BUFF * sizeof(uint8_t));

        free(AWPOOL[id].data);

        pthread_mutex_unlock(&AWPOOL[id].lock);

        printf("writer received: id: %d: data: %s\n", id, wdata);

        int wval = write(wfd, wdata, MAX_BUFF);

        printf("write data: %d\n", wval);


        free(wdata);

    }

}


/*
void handle_client(int i){

    int done = 0;


    while(TRUE){
        int valread;
        char buff[MAX_BUFF] = {0}; 
        char wbuff[MAX_BUFF] = {0};
        struct sockaddr_in peeraddr;
        socklen_t peerlen;

        peerlen = sizeof(peeraddr);

        valread = read(CLIENT_SOCKET[i].data.fd, buff, sizeof(buff));

        if(valread == -1){

            if(errno != EAGAIN){
                printf("handle read error\n");

                done = 1;                
            }

            break;


        } else if (valread == 0){


            getpeername(CLIENT_SOCKET[i].data.fd, (SA*)&peeraddr, &peerlen);
            printf("client disconnected: ip=%s, port=%d\n",
                inet_ntoa(peeraddr.sin_addr),
                ntohs(peeraddr.sin_port)
            );

            done = 1;

            break;

        }

        strcat(wbuff, "SERVER RESP: ");

        strcat(wbuff, buff);

        send(CLIENT_SOCKET[i].data.fd, wbuff, strlen(wbuff), 0);

    }

    if (done){

        close(CLIENT_SOCKET[i].data.fd);
        printf("closed sock\n");

    }



}
*/



