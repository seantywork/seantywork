#ifndef _QS_COMMON_H_
#define _QS_COMMON_H_


#include <string.h>
#include <stdio.h>
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

//#include "oqs/oqs.h"



#define THIS_SIG_NAME "mldsa65"
#define THIS_KEM_NAME "mlkem768"

#define DIGESTNAME NULL


#define T(e)                                                                   \
    if (!(e)) {                                                                \
        ERR_print_errors_fp(stderr);                                           \
        OPENSSL_die(#e, __FILE__, __LINE__);                                   \
    }

#define cRED "\033[1;31m"
#define cDRED "\033[0;31m"
#define cGREEN "\033[1;32m"
#define cDGREEN "\033[0;32m"
#define cBLUE "\033[1;34m"
#define cDBLUE "\033[0;34m"
#define cNORM "\033[m"


#define QS_DEFAULT_STRLEN 1024

extern OSSL_LIB_CTX *libctx;
//extern OSSL_PROVIDER *defaultprov;
//extern OSSL_PROVIDER *oqsprov;
//extern OSSL_PROVIDER *fibsprov;
//static OSSL_LIB_CTX *encodingctx = NULL;
//static OSSL_PROVIDER *encodingprov = NULL;
//extern char *modulename;
//extern char *configfile;
//extern OSSL_ALGORITHM *kemalgs;
//extern OSSL_ALGORITHM *sigalgs;

extern char *message;
extern int messagelen;


extern char *sig_name;
extern char *kem_name;
extern char group[QS_DEFAULT_STRLEN];
extern char certpath_ca[QS_DEFAULT_STRLEN];
extern char keypath_ca[QS_DEFAULT_STRLEN];
extern char pubpath_ca[QS_DEFAULT_STRLEN];
extern char certpath_c[QS_DEFAULT_STRLEN];
extern char keypath_c[QS_DEFAULT_STRLEN];
extern char pubpath_c[QS_DEFAULT_STRLEN];
extern char certpath[QS_DEFAULT_STRLEN];
extern char keypath[QS_DEFAULT_STRLEN];
extern char pubpath[QS_DEFAULT_STRLEN];
extern char kem_keypath_ca[QS_DEFAULT_STRLEN];
extern char kem_pubpath_ca[QS_DEFAULT_STRLEN];
extern char kem_keypath_c[QS_DEFAULT_STRLEN];
extern char kem_pubpath_c[QS_DEFAULT_STRLEN];
extern char kem_keypath[QS_DEFAULT_STRLEN];
extern char kem_pubpath[QS_DEFAULT_STRLEN];
extern char *certsdir;
#ifndef OPENSSL_SYS_VMS
extern char *sep;
#else
extern char *sep;
#endif


int create_key(OSSL_LIB_CTX *libctx, char *algname, char *privkeyfile_ca, char *pubkeyfile_ca, char *privkeyfile_c, char *pubkeyfile_c, char *privkeyfile, char *pubkeyfile);
int create_cert(OSSL_LIB_CTX *libctx, char *algname, char *certfilename_ca, char *key_ca, char *pub_ca, char *certfilename_c, char* pub_c, char *certfilename, char *pub);
int qs_init();
int qs_exit();
unsigned char* char2hex(int arrlen, unsigned char* bytearray);
unsigned char* hex2char(unsigned char* hexarray);



#endif