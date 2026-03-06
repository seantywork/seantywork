
#ifndef _SOCK_POLL_CLIENT_H_
#define _SOCK_POLL_CLIENT_H_


#include <stdio.h> 
#include <string.h> 
#include <stdlib.h>
#include <linux/limits.h>  
#include <unistd.h>

#include <pthread.h>

#include <arpa/inet.h>
#include <sys/socket.h>

#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <errno.h>

#define MAX_BUFFLEN 1024


extern int SOCK_FD;
int connect_with_timeout(char* addr, int port, long timeout);

#endif