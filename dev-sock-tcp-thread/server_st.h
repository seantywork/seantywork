#ifndef SERVER_ST_HEADER
#define SERVER_ST_HEADER

#include <stdio.h> 
#include <netdb.h> 
#include <netinet/in.h> 
#include <stdlib.h> 
#include <string.h> 
#include <sys/socket.h> 
#include <sys/types.h> 
#include <unistd.h> 
#include <time.h>
// s headers
#include <arpa/inet.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>

// t headers
#include <pthread.h>


#endif // SERVER_ST_HEADER

#ifndef SERVER_ST_HEADER_DEF
#define SERVER_ST_HEADER_DEF

#define TRUE 1
#define FALSE 0
#define MAX_BUFF 1024 
#define MAX_CONN 80
#define MAX_PORT 3
#define PORT1 8080 
#define PORT2 8090 
#define PORT3 8100 
#define SA struct sockaddr 
   



extern int SERVICE_PORTS[MAX_PORT];


extern pthread_t TID[MAX_PORT];
extern pthread_mutex_t TLOCK; 

struct WorkerArg {

    int WTHREAD_ID;
    int PORT;
};

extern struct WorkerArg WA[MAX_PORT];



void *Worker(void *); 
int msleep(long);


int make_socket_non_blocking (FILE* fp, int sfd);

void thandle_conn(FILE* fp, int SOCKFD, int EPLFD, struct epoll_event EVENT);

void thandle_client(FILE* fp, int i, struct epoll_event* CLIENT_SOCKET);


#endif