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
            
        }

        done = 1;      


    } else if (valread == 0){


        getpeername(CLIENT_SOCKET[i].data.fd, (SA*)&peeraddr, &peerlen);
        printf("client disconnected: ip=%s, port=%d\n",
            inet_ntoa(peeraddr.sin_addr),
            ntohs(peeraddr.sin_port)
        );

        done = 1;



    }

    strcat(wbuff, "SERVER RESP: ");

    strcat(wbuff, buff);

    send(CLIENT_SOCKET[i].data.fd, wbuff, strlen(wbuff), 0);



    if (done){

        close(CLIENT_SOCKET[i].data.fd);
        printf("closed sock\n");

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