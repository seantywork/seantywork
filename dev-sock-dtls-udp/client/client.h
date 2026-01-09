#ifndef _DTLS_CLIENT_
#define _DTLS_CLIENT_





#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>


#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>

#define CA_CERT "certs/ca.pem"
#define CA_KEY  "certs/ca_priv.pem"


#define BUFFER_SIZE          (1<<16)
#define COOKIE_SECRET_LENGTH 16


int handle_socket_error();

int dtls_verify_callback (int ok, X509_STORE_CTX *ctx);

void start_client(char *remote_address, char *local_address, int port, int length, int messagenumber);


#endif 