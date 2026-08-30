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
#include <netinet/tcp.h>

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
#include <urlparse.h>


#define H2_PORT 8888
#define H2_MAXCONN 32

#define H2_CA_CERT "tls/ca.crt"
#define H2_SERVER_CERT "tls/server.crt"

#define H2_SERVER_KEY "tls/server.key"
#define H2_CLIENT_CERT "tls/client.crt"
#define H2_CLIENT_KEY "tls/client.key"
#define H2_PREFERRED_CIPHERS "HIGH:!aNULL:!kRSA:!SRP:!PSK:!CAMELLIA:!RC4:!MD5:!DSS"

#define H2_MAX_CHUNK 4096

#define H2_URL "https://server.test:8888/index.html"

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

typedef struct http2_stream_data2 {
    /* The NULL-terminated URI string to retrieve. */
    const char *uri;
    /* Parsed result of the |uri| */
    urlparse_url *u;
    /* The authority portion of the |uri|, not NULL-terminated */
    char *authority;
    /* The path portion of the |uri|, including query, not
      NULL-terminated */
    char *path;
    /* The length of the |authority| */
    size_t authoritylen;
    /* The length of the |path| */
    size_t pathlen;
    /* The stream ID of this stream */
    int32_t stream_id;
} http2_stream_data2;

typedef struct sess_info2 sess_info2;

typedef struct sess_info2{
    int fd;
    SSL *ssl;
    struct http2_stream_data2 *stream_data;
    nghttp2_session *session;
} sess_info2;


int server_run(unsigned short port, char *ca_cert, char *server_cert, char *server_key);

int server_h2_recv(sess_info *session_data, unsigned char *data, size_t datalen);

int server_h2_send(sess_info *session_data);

int server_h2_alpn_select_proto_cb(SSL *ssl, const unsigned char **out,
                                unsigned char *outlen, const unsigned char *in,
                                unsigned int inlen, void *arg);

void server_h2_initialize_nghttp2_session(sess_info *session_data);

int server_h2_send_connection_header(sess_info *session_data);

int client_run(char *url, char *ca_cert, char *client_cert, char *client_key);

void client_h2_initialize_nghttp2_session(sess_info2 *session_data);

void client_h2_send_connection_header(sess_info2 *session_data);

void client_h2_submit_request(sess_info2 *session_data);

int client_h2_session_send(sess_info2 *session_data);

http2_stream_data2 *client_h2_create_http2_stream_data(const char *uri,
                                                   urlparse_url *u);

void client_h2_delete_http2_stream_data(http2_stream_data2 *stream_data);


#endif