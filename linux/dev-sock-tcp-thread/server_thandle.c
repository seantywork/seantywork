#include "server_st.h"

void thandle_conn(FILE* fp, int SOCKFD, int EPLFD, struct epoll_event EVENT){


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
                fprintf(fp, "all incoming connections handled\n");
                fflush(fp);
                break;

            } else{
                fprintf(fp, "errbo: %d\n", errno);
                fprintf(fp, "error handling incoming connection\n");
                fflush(fp);
                break;
            }
        }

        if(make_socket_non_blocking(fp, infd) < 0){
            fprintf(fp, "failed new conn non block\n");
            fflush(fp);
            exit(EXIT_FAILURE);
        }

        EVENT.data.fd = infd;
        EVENT.events = EPOLLIN | EPOLLET;

        if (epoll_ctl(EPLFD, EPOLL_CTL_ADD, infd, &EVENT) < 0){

            fprintf(fp, "handle epoll add failed\n");
            fflush(fp);
            exit(EXIT_FAILURE);

        }  else {

            fprintf(fp, "handle epoll add success\n");
            fflush(fp);

        }



    }



}


void thandle_client(FILE* fp, int i, struct epoll_event* CLIENT_SOCKET){

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
            fprintf(fp, "handle read error\n");
            fflush(fp);
            
        }

        done = 1;      


    } else if (valread == 0){


        getpeername(CLIENT_SOCKET[i].data.fd, (SA*)&peeraddr, &peerlen);
        fprintf(fp, "client disconnected: ip=%s, port=%d\n",
            inet_ntoa(peeraddr.sin_addr),
            ntohs(peeraddr.sin_port)
        );
        fflush(fp);

        done = 1;



    }

    strcat(wbuff, "SERVER RESP: ");

    strcat(wbuff, buff);

    send(CLIENT_SOCKET[i].data.fd, wbuff, strlen(wbuff), 0);



    if (done){

        close(CLIENT_SOCKET[i].data.fd);
        fprintf(fp, "closed sock\n");
        fflush(fp);

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