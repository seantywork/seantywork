#include "server.h"

void handle_conn(){


    while(TRUE){

        struct sockaddr in_addr;
        socklen_t in_len;
        int infd;
        SSL *ssl;
        SSL_CTX *ctx;

        int ssl_accept_ret;

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

                printf("error handling incoming connection\n");
                break;
            }
        }

        ctx = create_context();

        configure_context(ctx);

        ssl = SSL_new(ctx);

        SSL_set_fd(ssl, infd);

    
        if((ssl_accept_ret = SSL_accept(ssl)) < 1){

            int sslerr =  SSL_get_error(ssl, 0);

            printf("error handling tls handshake\n");

            if (ssl_accept_ret <=0 && (sslerr == SSL_ERROR_WANT_READ)) {

                perror ("Need to wait until socket is readable.");

            } else if (ssl_accept_ret <=0 && (sslerr == SSL_ERROR_WANT_WRITE)) {

                perror ("Need to wait until socket is writable.");

            } else {
                perror ("Need to wait until socket is ready.");
            }

            shutdown (infd, 2);
            SSL_free (ssl);
            SSL_CTX_free(ctx);

            continue;

        } 


        if(make_socket_non_blocking(infd) < 0){
            printf("failed new conn non block\n");
            exit(EXIT_FAILURE);
        }


        set_tlsch(infd, ssl, ctx);


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



void handle_client(int cfd){

    int done = 0;

    FILE  *fp;

    char f_name[10] = {0};

    sprintf(f_name, "%d", cfd);

    fp = fopen(f_name, "a");

    
    int valread;
    char buff[MAX_BUFF] = {0}; 
    char wbuff[MAX_BUFF] = {0}; 
    struct sockaddr_in peeraddr;
    socklen_t peerlen;

    SSL * sslst;

    peerlen = sizeof(peeraddr);

    sslst = get_tlsch_ssl(cfd);

    valread = SSL_read(sslst, buff,sizeof(buff));

    fprintf(fp,"read %d\n",valread);
    fflush(fp);

    if(valread == -1){

        if(errno != EAGAIN){
            printf("handle read error\n");
        }

        done = 1;


    } else if (valread == 0){

        getpeername(cfd, (SA*)&peeraddr, &peerlen);
        printf("client disconnected: ip=%s, port=%d\n",
            inet_ntoa(peeraddr.sin_addr),
            ntohs(peeraddr.sin_port)
        );

        done = 1;


    }


    strcat(wbuff,"SSL SERVER RESP: ");

    strcat(wbuff, buff);

    sleep(WAIT);


    SSL_write(sslst, wbuff, sizeof(wbuff));

    if (done){

        release_tlsch(cfd);
        close(cfd);

        printf("closed sock\n");

    }



}


/*

void handle_client(int cfd){

    int done = 0;

    FILE  *fp;

    char f_name[10] = {0};

    sprintf(f_name, "%d", cfd);

    fp = fopen(f_name, "a");

    while(TRUE){
        int valread;
        char buff[MAX_BUFF] = {0}; 
        struct sockaddr_in peeraddr;
        socklen_t peerlen;

        SSL * sslst;

        peerlen = sizeof(peeraddr);

        sslst = get_tlsch_ssl(cfd);

        valread = SSL_read(sslst, buff,sizeof(buff));

        fprintf(fp,"read %d\n",valread);
        fflush(fp);

        if(valread == -1){

            if(errno != EAGAIN){
                printf("handle read error\n");
                done = 1;
            }

            break;


        } else if (valread == 0){

            getpeername(cfd, (SA*)&peeraddr, &peerlen);
            printf("client disconnected: ip=%s, port=%d\n",
                inet_ntoa(peeraddr.sin_addr),
                ntohs(peeraddr.sin_port)
            );

            done = 1;

            break;

        }

        SSL_write(sslst, buff, sizeof(buff));
    }

    if (done){

        release_tlsch(cfd);
        close(cfd);

        printf("closed sock\n");

    }



}

*/