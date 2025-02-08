
#include "server_ep.h"



struct sockaddr_in SERVADDR;
int SERVLEN;

int SOCKFD;
int EPLFD;
int MAX_SD;

int OPT = TRUE;

struct epoll_event EVENT;
struct epoll_event *CLIENT_SOCKET;
pthread_t *WORK_PID;
pthread_t *WRITE_PID;
int *APOOL_ID;
async_pool *APOOL;
async_pool *AWPOOL;

int main() 
{ 



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
    

    if ((listen(SOCKFD, 10)) != 0) { 
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

    WORK_PID = calloc(MAX_CONN, sizeof(pthread_t));

    WRITE_PID = calloc(MAX_CONN, sizeof(pthread_t));

    APOOL_ID = calloc(MAX_CONN, sizeof(int));

    APOOL = calloc(MAX_CONN, sizeof(async_pool));

    AWPOOL = calloc(MAX_CONN, sizeof(async_pool));

    for(int i = 0 ; i < MAX_CONN; i++){

        APOOL_ID[i] = i;


        pthread_mutex_init(&APOOL[i].lock, NULL);
        pthread_mutex_init(&AWPOOL[i].lock, NULL);

        pthread_cond_init(&APOOL[i].cond, NULL);
        pthread_cond_init(&AWPOOL[i].cond, NULL);


        pthread_create(&WORK_PID[i], NULL, worker, (void*)&APOOL_ID[i]);

        pthread_create(&WRITE_PID[i], NULL, writer, (void*)&APOOL_ID[i]);

    }

    printf("thread pool created: %d\n", MAX_CONN);

    while(TRUE){

        int n, i ;

        n = epoll_wait(EPLFD, CLIENT_SOCKET, MAX_CONN, -1);

        for (i = 0 ; i < n; i ++){

            if (
                (CLIENT_SOCKET[i].events & EPOLLERR) ||
                (CLIENT_SOCKET[i].events & EPOLLHUP) ||
                (!(CLIENT_SOCKET[i].events & EPOLLIN))
            ){

                printf("epoll wait error \n");
                close(CLIENT_SOCKET[i].data.fd);
                continue;

            } else if (SOCKFD == CLIENT_SOCKET[i].data.fd){

                handle_conn();

                printf("new conn successfully handled\n");

                continue;

            } else{

               handle_client(i);

               printf("socket data successfully handled\n");


            }

        }


    }


    free(CLIENT_SOCKET);

    free(WORK_PID);

    free(WRITE_PID);

    free(APOOL_ID);

    free(APOOL);

    free(AWPOOL);

    close(SOCKFD);

    close(EPLFD);


    return EXIT_SUCCESS;
}