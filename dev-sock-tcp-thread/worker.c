
#include "server_st.h"



void* Worker(void* vargp){

    int alive = TRUE;

    FILE *fp;

    int sd;
    int tport;
    int valread;
    char buff[MAX_BUFF]; 
    struct sockaddr_in peeraddr;

    struct sockaddr_in SERVADDR;
    int SERVLEN;
    int SOCKFD;
    int EPLFD;
    int MAX_SD;

    int OPT = TRUE;

    struct epoll_event EVENT;
    struct epoll_event *CLIENT_SOCKET;

    char f_name[10] = {0};

    struct WorkerArg* warg = (struct WorkerArg* )vargp;

    int wk_tid = warg->WTHREAD_ID;

    tport = warg->PORT;

    sprintf(f_name,"%d",tport);

    fp = fopen(f_name, "a");
    
    
    SOCKFD = socket(AF_INET, SOCK_STREAM, 0); 

    if (SOCKFD == -1) { 
        fprintf(fp, "socket creation failed\n"); 
        fflush(fp);
        exit(EXIT_FAILURE); 
    } 
    else
        fprintf(fp, "socket successfully created\n"); 
        fflush(fp);

    
    if( setsockopt(SOCKFD, SOL_SOCKET, SO_REUSEADDR, (char *)&OPT,  
          sizeof(OPT)) < 0 )   
    {   
        fprintf(fp, "setsockopt");   
        fflush(fp);
        exit(EXIT_FAILURE);   
    } 

      

    bzero(&SERVADDR, sizeof(SERVADDR)); 
   
    SERVADDR.sin_family = AF_INET; 
    SERVADDR.sin_addr.s_addr = htonl(INADDR_ANY); 
    SERVADDR.sin_port = htons(tport); 
   
    if ((bind(SOCKFD, (SA*)&SERVADDR, sizeof(SERVADDR))) != 0) { 
        fprintf(fp, "socket bind failed\n"); 
        fflush(fp);
        exit(EXIT_FAILURE); 
    } 
    
    if(make_socket_non_blocking(fp, SOCKFD) < 0){
        fprintf(fp, "non-blocking failed\n");
        fflush(fp);
        exit(EXIT_FAILURE);
    }
    

    if ((listen(SOCKFD, 10)) != 0) { 
        fprintf(fp, "listen failed\n");
        fflush(fp); 
        exit(EXIT_FAILURE); 
    } 
    else{
        SERVLEN = sizeof(SERVADDR); 
    }


    EPLFD = epoll_create1(0);

    if(EPLFD == -1){
        fprintf(fp, "epoll creation failed \n");
        fflush(fp);
        exit(EXIT_FAILURE);
    }

    EVENT.data.fd = SOCKFD;
    EVENT.events = EPOLLIN | EPOLLET;
    
    if (epoll_ctl(EPLFD, EPOLL_CTL_ADD, SOCKFD, &EVENT) < 0){
        fprintf(fp, "epoll add failed\n");
        fflush(fp);
        exit(EXIT_FAILURE);
    }    

    CLIENT_SOCKET = calloc(MAX_CONN, sizeof(EVENT));


    while(TRUE){

        int n, i ;

        n = epoll_wait(EPLFD, CLIENT_SOCKET, MAX_CONN, -1);

        for (i = 0 ; i < MAX_CONN; i ++){

            if (
                (CLIENT_SOCKET[i].events & EPOLLERR) ||
                (CLIENT_SOCKET[i].events & EPOLLHUP) ||
                (!(CLIENT_SOCKET[i].events & EPOLLIN))
            ){

                fprintf(fp, "epoll wait error \n");
                fflush(fp);
                close(CLIENT_SOCKET[i].data.fd);
                continue;

            } else if (SOCKFD == CLIENT_SOCKET[i].data.fd){

                thandle_conn(fp, SOCKFD, EPLFD, EVENT);

                fprintf(fp, "new conn successfully handled\n");
                fflush(fp);

                continue;

            } else{

               thandle_client(fp, i, CLIENT_SOCKET);

               fprintf(fp, "socket data successfully handled\n");
               fflush(fp);


            }

        }


    }


    free(CLIENT_SOCKET);

    close(SOCKFD);

    close(EPLFD);

    fclose(fp);


}

int msleep(long msec)
{
    struct timespec ts;
    int res;

    if (msec < 0)
    {
        errno = EINVAL;
        return -1;
    }

    ts.tv_sec = msec / 1000;
    ts.tv_nsec = (msec % 1000) * 1000000;

    do {
        res = nanosleep(&ts, &ts);
    } while (res && errno == EINTR);

    return res;
}