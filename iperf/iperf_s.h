#ifndef _IPERF_S_H_
#define _IPERF_S_H_

#include <stdio.h> 
#include <netdb.h> 
#include <netinet/in.h> 
#include <arpa/inet.h>
#include <stdlib.h> 
#include <string.h> 
#include <sys/socket.h> 
#include <sys/types.h> 
#include <unistd.h> 
#include <stdint.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>

#define MAXCLIENT 32
#define MAXBUFFLEN 65536

extern char mode;
extern unsigned short port;
extern int client_num;
extern uint8_t client_buff[MAXCLIENT][MAXBUFFLEN];

int make_socket_non_blocking (int sfd);

void* ctl_runner(void* varg);

int run_select(int fd, struct sockaddr_in* servaddr);

int run_poll(int fd, struct sockaddr_in* servaddr);

int run_epoll(int fd, struct sockaddr_in* servaddr);




#endif