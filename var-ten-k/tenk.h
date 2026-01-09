#ifndef _TEN_K_H_
#define _TEN_K_H_

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
#include <sys/epoll.h>
#include <errno.h>
#include <stdatomic.h>
#include <sys/time.h>
#include <sys/random.h>

#define MAXCLIENT 10000
#define CLIENTS_PER_THREAD 100
#define THREAD_ITER 100
#define MAXBUFFLEN 65536
#define PORT 9999

extern char mode;
extern char server_mode;

extern int client_num;
extern uint8_t** client_buff;

extern int wfds[MAXCLIENT];
extern uint8_t wbuff[MAXCLIENT / CLIENTS_PER_THREAD][MAXBUFFLEN];
extern atomic_uint_fast8_t wdones[MAXCLIENT / CLIENTS_PER_THREAD];


void* run_client_thread(void* varg);

int make_socket_non_blocking (int sfd);



int run_select(int fd, struct sockaddr_in* servaddr);

int run_poll(int fd, struct sockaddr_in* servaddr);

int run_epoll(int fd, struct sockaddr_in* servaddr);




#endif