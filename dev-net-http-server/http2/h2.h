#ifndef _H2_H_ 
#define _H2_H_


#include <stdio.h> 
#include <netinet/in.h> 
#include <stdlib.h> 
#include <string.h> 
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>  
#include <sys/random.h>
#include <unistd.h> 
#include <time.h>
#include <endian.h>
#include <pthread.h>
#include <stdarg.h>
#include <sys/time.h>
#include <poll.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h> 
#include <ctype.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/buffer.h>
#include <openssl/x509v3.h>
#include <openssl/opensslconf.h>

#include <nghttp2/nghttp2.h>

#define H2_PORT 8888
#define H2_MAXCONN 32

#define H2_CA_CERT "tls/ca.crt"
#define H2_SERVER_CERT "tls/server.crt"

#define H2_SERVER_KEY "tls/server.key"
#define H2_CLIENT_CERT "tls/client.crt"
#define H2_CLIENT_KEY "tls/client.key"
#define H2_PREFERRED_CIPHERS "HIGH:!aNULL:!kRSA:!SRP:!PSK:!CAMELLIA:!RC4:!MD5:!DSS"

#define H2_MAX_CHUNK 4096

#define ARRLEN(x) (sizeof(x) / sizeof(x[0]))

#define MAKE_NV(NAME, VALUE)                                                   \
  {                                                                            \
    (uint8_t *)NAME,   (uint8_t *)VALUE,     sizeof(NAME) - 1,                 \
    sizeof(VALUE) - 1, NGHTTP2_NV_FLAG_NONE,                                   \
  }

typedef struct http2_stream_data {
    struct http2_stream_data *prev, *next;
    char *request_path;
    int32_t stream_id;
    int fd;
} http2_stream_data;

typedef struct sess_info sess_info;

typedef struct sess_info{
    int fd;
    SSL *ssl;
    struct http2_stream_data root;
    nghttp2_session *session;
    char *client_addr;
    sess_info *self;
} sess_info;

int server_run(unsigned short port, char *ca_cert, char *server_cert, char *server_key);

int server_h2_recv(sess_info *session_data, unsigned char *data, size_t datalen);

int server_h2_send(sess_info *session_data);

int server_h2_alpn_select_proto_cb(SSL *ssl, const unsigned char **out,
                                unsigned char *outlen, const unsigned char *in,
                                unsigned int inlen, void *arg);

void server_h2_initialize_nghttp2_session(sess_info *session_data);

int server_h2_send_connection_header(sess_info *session_data);


#endif