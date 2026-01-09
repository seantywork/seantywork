#ifndef _SERVER_POLL_H_
#define _SERVER_POLL_H_


#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <poll.h>

#include <fcntl.h>
#include <errno.h>

#define PORT 8080
#define SIZE 1024
#define MAX_CLIENTS 10
#define WAIT 3

int make_socket_non_blocking (int sfd);

#endif