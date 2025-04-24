#ifndef _NCAT_H_
#define _NCAT_H_

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

#define INPUT_BUFF_CHUNK 1024
#define SERVER_SIG_DONE "done"
#define SERVER_SIG_LEN     4
#define SERVER_SIG_TIMEOUT_COUNT 5
#define SERVER_SIG_TIMEOUT_MS 100
#define CLIENT_EXIT     "exit"

typedef struct NCAT_OPTIONS {

    int mode_client;
    int mode_listen;
    int _client_sock_ready;
    int _client_sockfd;
    int _server_sig[2];
    char* host;
    char* port;

} NCAT_OPTIONS;

typedef struct __attribute__((packed)) NCAT_COMMS {
    uint32_t datalen;
    uint8_t* data;
} NCAT_COMMS;

extern NCAT_OPTIONS ncat_opts;
extern char* serve_content;
extern int _exit_prog;

void NCAT_keyboard_interrupt();

int NCAT_parse_args(int argc, char** argv);


void NCAT_free();


int NCAT_runner();


int NCAT_client();


int NCAT_listen_and_serve();



void* NCAT_get_thread();



void msleep(long ms);

#endif