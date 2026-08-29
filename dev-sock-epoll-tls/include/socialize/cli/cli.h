#ifndef _SOCIALIZE_CLI_H_
#define _SOCIALIZE_CLI_H_

#include "socialize/core.h"


#ifndef VERIFICATION_LOCATION
# define VERIFICATION_LOCATION "tls/ca.crt.pem"
#endif


# define ASSERT(x) { \
  if(!(x)) { \
    fprintf(stderr, "Assertion: %s: function %s, line %d\n", (char*)(__FILE__), (char*)(__func__), (int)__LINE__); \
    exit(SIGTRAP); \
  } \
}




int run_cli(char* addr);


int connect_to_engine(char* addr, long timeout);

int auth();

int join();

int socialize();

void* reader(void *varg);



int verify_callback(int preverify, X509_STORE_CTX* x509_ctx);

void init_openssl_library(void);
void print_cn_name(const char* label, X509_NAME* const name);
void print_san_name(const char* label, X509* const cert);
void print_error_string(unsigned long err, const char* const label);

extern int cli_done;
extern char* PREFERRED_CIPHERS;

extern char* CERT_LOC;
extern int TEST_CASE;

extern SSL_CTX* ctx;
extern SSL *ssl ;

extern uint8_t header[HUB_HEADER_BYTELEN];
extern uint8_t body_len[HUB_BODY_BYTELEN];
extern uint64_t body_len_new;
extern uint8_t *body;

#endif 
