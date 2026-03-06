
#ifndef _SOCK_SELECT_H_
#define _SOCK_SELECT_H_


#include <stdio.h> 
#include <netdb.h> 
#include <netinet/in.h> 
#include <stdlib.h> 
#include <string.h> 
#include <sys/socket.h> 
#include <sys/types.h> 
#include <unistd.h> 
// m headers
#include <errno.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include <fcntl.h>


#define TRUE 1
#define FALSE 0
#define MAX_BUFF 1024 
#define MAX_CONN 80
#define PORT 8080 
#define SA struct sockaddr 

int make_socket_non_blocking (int sfd);


#endif