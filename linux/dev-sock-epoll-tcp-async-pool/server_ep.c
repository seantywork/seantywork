
#include "server_ep.h"



struct sockaddr_in SERVADDR;
int SERVLEN;

int SOCKFD;
int EPLFD;
int MAX_SD;

int OPT = TRUE;

struct epoll_event EVENT;
struct epoll_event *CLIENT_SOCKET;
pthread_t *WORK_TID;
worker_t *WORKERS;

int main() { 
    work_queue_bucket* wq = work_queue_make(MAX_JOB);
    SOCKFD = socket(AF_INET, SOCK_STREAM, 0); 
    if (SOCKFD == -1) { 
        printf("socket creation failed\n"); 
        exit(EXIT_FAILURE); 
    } 
    else
        printf("socket successfully created\n"); 

    
    if( setsockopt(SOCKFD, SOL_SOCKET, SO_REUSEADDR, (char *)&OPT,  
          sizeof(OPT)) < 0 )   
    {   
        perror("setsockopt");   
        exit(EXIT_FAILURE);   
    } 
      
    bzero(&SERVADDR, sizeof(SERVADDR)); 
    SERVADDR.sin_family = AF_INET; 
    SERVADDR.sin_addr.s_addr = htonl(INADDR_ANY); 
    SERVADDR.sin_port = htons(PORT); 
    if ((bind(SOCKFD, (SA*)&SERVADDR, sizeof(SERVADDR))) != 0) { 
        printf("socket bind failed\n"); 
        exit(EXIT_FAILURE); 
    } 
    if(make_socket_non_blocking(SOCKFD) < 0){
        printf("non-blocking failed\n");
        exit(EXIT_FAILURE);
    }
    if ((listen(SOCKFD, MAX_CONN)) != 0) { 
        printf("listen failed\n"); 
        exit(EXIT_FAILURE); 
    } 
    else{
        SERVLEN = sizeof(SERVADDR); 
    }
    EPLFD = epoll_create1(0);
    if(EPLFD == -1){
        printf("epoll creation failed \n");
        exit(EXIT_FAILURE);
    }
    EVENT.data.fd = SOCKFD;
    EVENT.events = EPOLLIN | EPOLLET;
    if (epoll_ctl(EPLFD, EPOLL_CTL_ADD, SOCKFD, &EVENT) < 0){
        printf("epoll add failed\n");
        exit(EXIT_FAILURE);
    }    
    CLIENT_SOCKET = calloc(MAX_CONN, sizeof(EVENT));
    WORK_TID = calloc(MAX_WORKER, sizeof(pthread_t));
    WORKERS = calloc(MAX_WORKER, sizeof(worker_t));
    for(int i = 0 ; i < MAX_WORKER; i++){
        WORKERS[i].id = i;
        WORKERS[i].work_queue = (void*)wq;
        pthread_create(&WORK_TID[i], NULL, worker, (void*)&WORKERS[i]);
    }
    printf("thread pool created: %d\n", MAX_WORKER);
    while(TRUE){
        int n, i;
        n = epoll_wait(EPLFD, CLIENT_SOCKET, MAX_CONN, -1);
        for (i = 0 ; i < n; i ++){
            if (
                (CLIENT_SOCKET[i].events & EPOLLERR) ||
                (CLIENT_SOCKET[i].events & EPOLLHUP) ||
                (!(CLIENT_SOCKET[i].events & EPOLLIN))
            ){
                printf("epoll wait error \n");
                close(CLIENT_SOCKET[i].data.fd);
            } else if (SOCKFD == CLIENT_SOCKET[i].data.fd){
                printf("conn event\n");
                job_t* j = new_job();
                conn_context_t* ctx = (conn_context_t*)malloc(sizeof(conn_context_t));
                ctx->eplfd = EPLFD;
                ctx->fd = SOCKFD;
                j->data = (void*)ctx;
                j->job = handle_conn;
                work_queue_en(wq, &j);
                printf("conn scheduled\n");
            } else{
                printf("read event\n");
                job_t* j = new_job();
                read_context_t* ctx = (read_context_t*)malloc(sizeof(read_context_t));
                ctx->fd = CLIENT_SOCKET[i].data.fd;
                j->data = (void*)ctx;
                j->job = handle_read;
                work_queue_en(wq, &j);
                printf("read event scheduled\n");
            }
        }
    }

    free(CLIENT_SOCKET);
    free(WORK_TID);
    free(WORKERS);
    close(SOCKFD);
    close(EPLFD);
    work_queue_delete(wq);

    return EXIT_SUCCESS;
}



