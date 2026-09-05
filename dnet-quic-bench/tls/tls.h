#ifndef _BENCH_TLS_H_
#define _BENCH_TLS_H_

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

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/buffer.h>
#include <openssl/x509v3.h>
#include <openssl/opensslconf.h>



#define SERVER_ADDR "quicbench"
#define SERVER_PORT 9999
#define INPUT_BUFF_CHUNK 65536
#define INPUT_BUFF_MAX 4294967296


#define CERT_CA  "certs/ca.pem"
#define CERT_SERVER "certs/server.crt.pem"
#define KEY_SERVER "certs/server.key.pem"

#endif