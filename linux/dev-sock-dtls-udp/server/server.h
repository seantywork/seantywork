#ifndef _DTLS_SERVER_
#define _DTLS_SERVER_






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

#define SERVER_CERT "certs/server.pem"
#define SERVER_KEY  "certs/server.key"

#define BUFFER_SIZE          (1<<16)
#define COOKIE_SECRET_LENGTH 16


struct pass_info {
	union {
		struct sockaddr_storage ss;
		struct sockaddr_in6 s6;
		struct sockaddr_in s4;
	} server_addr, client_addr;
	SSL *ssl;
};



extern unsigned char cookie_secret[COOKIE_SECRET_LENGTH];
extern int cookie_initialized;

int handle_socket_error();

int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len);


int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len);


int dtls_verify_callback (int ok, X509_STORE_CTX *ctx);


void connection_handle(struct pass_info *info);

void start_server(int port, char *local_address);

#endif