
#ifndef _SOCK_SELECT_CLIENT_H_
#define _SOCK_SELECT_CLIENT_H_


#include <arpa/inet.h> // inet_addr()
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h> // bzero()
#include <sys/socket.h>
#include <unistd.h> // read(), write(), close()

#include <errno.h>
#include <sys/time.h>

#include <fcntl.h>
#include <time.h>

#define MAX 80
#define PORT 8080
#define SA struct sockaddr


extern int SOCK_FD;

#endif

