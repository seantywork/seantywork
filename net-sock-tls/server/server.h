#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


#ifndef SERVER_KEY
# define SERVER_KEY "certs/server.key"
#endif

#ifndef SERVER_CERT
# define SERVER_CERT "certs/server.pem"
#endif


int create_socket(int port);

SSL_CTX *create_context();


void configure_context(SSL_CTX *ctx);

void comm(SSL* ssl);

