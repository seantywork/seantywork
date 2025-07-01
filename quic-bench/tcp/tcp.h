#ifndef _BENCH_TCP_H_
#define _BENCH_TCP_H_

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
#include <sys/random.h>
#include <inttypes.h>




#define SERVER_ADDR "192.168.62.6"
#define SERVER_PORT 9999
#define INPUT_BUFF_CHUNK 65536
#define INPUT_BUFF_MAX 4294967296


#endif