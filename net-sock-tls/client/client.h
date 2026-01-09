#ifndef __PUBKEY_PIN_INCLUDED__
#define __PUBKEY_PIN_INCLUDED__

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netdb.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/buffer.h>
#include <openssl/x509v3.h>
#include <openssl/opensslconf.h>

#ifndef UNUSED
# define UNUSED(x) ((void)(x))
#endif

#ifndef TRUE
# define TRUE 1
#endif

#ifndef FALSE
# define FALSE 0
#endif

#ifndef HOST_NAME
# define HOST_NAME "localhost"
#endif

#ifndef HOST_PORT
# define HOST_PORT "4004"
#endif

#ifndef VERIFICATION_LOCATION
# define VERIFICATION_LOCATION "certs/ca.pem"
#endif

#ifndef HOST_RESOURCE
# define HOST_RESOURCE "/cgi-bin/randbyte?nbytes=32&format=h"
#endif

#ifndef SIGTRAP
# define SIGTRAP 1337
#endif

# define ASSERT(x) { \
  if(!(x)) { \
    fprintf(stderr, "Assertion: %s: function %s, line %d\n", (char*)(__FILE__), (char*)(__func__), (int)__LINE__); \
    exit(SIGTRAP); \
  } \
}

#endif // __PUBKEY_PIN_INCLUDED__

int verify_callback(int preverify, X509_STORE_CTX* x509_ctx);

void init_openssl_library(void);
void print_cn_name(const char* label, X509_NAME* const name);
void print_san_name(const char* label, X509* const cert);
void print_error_string(unsigned long err, const char* const label);