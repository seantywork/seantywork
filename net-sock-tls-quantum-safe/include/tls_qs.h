#ifndef _TLS_QS_H_
#define _TLS_QS_H_


#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/trace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pthread.h>

#include "oqs/oqs.h"

#define THIS_PROVIDER "oqsprovider"
#define THIS_CONFFILE "/usr/local/ssl/openssl.cnf"

#define THIS_SIGNATURE_ALGORITHM "mldsa65"
#define THIS_KEM_ALGORITHM "mlkem768"

#define CA_CERT "ca.crt.pem"
#define SERVER_CERT "srv.crt.pem"
#define SERVER_KEY "srv.key.pem"

#define RWBUFF_LEN 1024

#define T(e)                                                                   \
    if (!(e)) {                                                                \
        ERR_print_errors_fp(stderr);                                           \
        OPENSSL_die(#e, __FILE__, __LINE__);                                   \
    }

void load_oqs_provider(OSSL_LIB_CTX *libctx, const char *modulename, const char *configfile);

#endif 