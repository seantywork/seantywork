#ifndef _QS_TLS_H_
#define _QS_TLS_H_

#include "qs_common.h"



int create_cert_key(OSSL_LIB_CTX *libctx, char *algname, char *certfilename,
    char *privkeyfilename);

int create_tls1_3_ctx_pair(OSSL_LIB_CTX *libctx, SSL_CTX **sctx, SSL_CTX **cctx,
           char *certfile, char *privkeyfile, int dtls_flag);

int create_tls_objects(SSL_CTX *serverctx, SSL_CTX *clientctx, SSL **sssl,
       SSL **cssl, int use_dgram);

int create_tls_connection(SSL *serverssl, SSL *clientssl, int want);

#endif