#ifndef _BENCH_QUIC_H_
#define _BENCH_QUIC_H_

#include "msquic.h"
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

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(P) (void)(P)
#endif

#define SERVER_ADDR "quicbench"
#define SERVER_PORT 9999
#define INPUT_BUFF_CHUNK 65536
//#define INPUT_BUFF_CHUNK 100
//#define INPUT_BUFF_MAX 4294967296
#define INPUT_BUFF_MAX 8388608
#define CERT_CA "certs/ca.pem"
#define CERT_SERVER "certs/server.crt.pem"
#define KEY_SERVER "certs/server.key.pem"
#define CERT_CLIENT "certs/client.crt.pem"
#define KEY_CLIENT "certs/client.key.pem"

typedef struct QUIC_CREDENTIAL_CONFIG_HELPER {
    QUIC_CREDENTIAL_CONFIG CredConfig;
    union {
        QUIC_CERTIFICATE_HASH CertHash;
        QUIC_CERTIFICATE_HASH_STORE CertHashStore;
        QUIC_CERTIFICATE_FILE CertFile;
        QUIC_CERTIFICATE_FILE_PROTECTED CertFileProtected;
    };
} QUIC_CREDENTIAL_CONFIG_HELPER;


extern QUIC_REGISTRATION_CONFIG quic_req_config;

extern QUIC_BUFFER quic_alpn;

extern uint16_t quic_udp_port;

extern uint64_t quic_idle_timeoutms;

extern uint32_t quic_send_buffer_len;

extern QUIC_API_TABLE* quic_api;

extern HQUIC quic_registration;

extern HQUIC quic_configuration;

extern QUIC_TLS_SECRETS quic_client_secrets;

extern char* quic_ssl_keylog_env;




#endif