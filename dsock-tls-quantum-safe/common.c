#include "tls_qs.h"


void load_oqs_provider(OSSL_LIB_CTX *libctx, const char *modulename, const char *configfile) {

    T(OSSL_LIB_CTX_load_config(libctx, configfile));
    T(OSSL_PROVIDER_available(libctx, modulename));
}
