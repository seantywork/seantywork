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
// ep headers
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>
#include <arpa/inet.h>



#endif // SERVER_ST_HEADER

#ifndef SERVER_EP_HEADER_DEF
#define SERVER_EP_HEADER_DEF

#define TRUE 1
#define FALSE 0
#define MAX_BUFF 1024 
#define MAX_CONN 80
#define PORT 8080 
#define SA struct sockaddr 
   
extern struct sockaddr_in SERVADDR;
extern int SERVLEN;

extern int SOCKFD;
extern int EPLFD;
extern int MAX_SD;

extern int OPT;

extern struct epoll_event EVENT;
extern struct epoll_event *CLIENT_SOCKET;


int make_socket_non_blocking (int);

void handle_conn();

void handle_client(int);

#endif