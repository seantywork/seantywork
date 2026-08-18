#ifndef _SOCK_QUIC_H_
#define _SOCK_QUIC_H_

#include "msquic.h"
#include <stdio.h>
#include <stdlib.h>

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(P) (void)(P)
#endif


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