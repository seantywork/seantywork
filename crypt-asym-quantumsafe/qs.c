

#include "qs_common.h"

static OSSL_LIB_CTX *libctx = NULL;
static char *modulename = NULL;
static char *configfile = NULL;

static char *message = "cryptoinccryptoinccryptoinccryptoinccryptoinccryptoinccryptoinccryptoinccryptoinccryptoinccryptoinccryptoinccryptoinccryptoinccryptoinccryptoinccryptoinccryptoinccryptoinccryptoinc";
static int messagelen = 0;

FILE* fp;

static int qs_encdec(const char *kemalg_name) {
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;
    unsigned char *out = NULL;
    unsigned char *secenc = NULL;
    unsigned char *secdec = NULL;
    size_t outlen, seclen;

    BIO *bp_public;
    BIO *bp_private;

    int result = 1;

    if (!alg_is_enabled(kemalg_name)) {
        printf("Not testing disabled algorithm %s.\n", kemalg_name);
        return 1;
    }
    // limit to oqsprovider as other implementations may support
    // different key formats than what is defined by NIST
    if (OSSL_PROVIDER_available(libctx, "default")) {

        ctx = EVP_PKEY_CTX_new_from_name(libctx, kemalg_name, OQSPROV_PROPQ);

        if (ctx == NULL){

            printf("ctx is null\n");

            result = -1;

            goto err;

        }

        result = EVP_PKEY_keygen_init(ctx); 

        if(result != 1){
            printf("keygen init failed\n");
            result -1;
            goto err;
        }

        result = EVP_PKEY_generate(ctx, &key);

        if(result != 1){
            printf("keygen failed\n");
            result -1;
            goto err;
        }

        bp_private = BIO_new(BIO_s_mem());
        bp_public = BIO_new(BIO_s_mem());

        result = PEM_write_bio_PrivateKey(bp_private, key, NULL, NULL, 0, NULL, NULL);

        if(result != 1){
            printf("privatekey failed\n");
            result -1;
            goto err;
        }

        result = PEM_write_bio_PUBKEY(bp_public, key);

        if(result != 1){
            printf("pubkey failed\n");
            result -1;
            goto err;
        }
        printf("done\n");

        unsigned char *membuff;

        int memlen = BIO_get_mem_data(bp_private, &membuff);

        printf("%s\n", membuff);

        memlen = BIO_get_mem_data(bp_public, &membuff);

        printf("%s\n", membuff);


        EVP_PKEY_CTX_free(ctx);
        ctx = NULL;

        ctx = EVP_PKEY_CTX_new_from_pkey(libctx, key, OQSPROV_PROPQ);

        if(ctx == NULL){

            printf("get key failed\n");

            result = -1;

            goto err;
        }

        result = EVP_PKEY_encapsulate_init(ctx, NULL);

        if(result != 1){
            printf("encap init failed\n");
            result -1;
            goto err;
        }

        result = EVP_PKEY_encapsulate(ctx, NULL, &outlen, NULL, &seclen);

        if(result != 1){
            printf("encap failed\n");
            result -1;
            goto err;
        }

        out = OPENSSL_malloc(outlen);

        if(out == NULL){
            printf("malloc out failed\n");
            result -1;
            goto err;
        }

        secenc = OPENSSL_malloc(seclen);

        if(secenc == NULL){
            printf("malloc secenc failed\n");
            result -1;
            goto err;
        }

        printf("messagelen: %d outlen: %d seclen: %d\n", messagelen, outlen, seclen);

        for(int i = 0; i < seclen; i++){

            secenc[i] = message[i];
        }


        secdec = OPENSSL_malloc(seclen);

        if(secdec == NULL){
            printf("malloc secdec failed\n");
            result -1;
            goto err;
        }

        memset(secdec, 0xff, seclen);

        result = EVP_PKEY_encapsulate(ctx, out, &outlen, secenc, &seclen);

        if(result != 1){
            printf("encap run failed\n");
            result -1;
            goto err;
        }

        result = EVP_PKEY_decapsulate_init(ctx, NULL);

        if(result != 1){
            printf("decap init failed\n");
            result -1;
            goto err;
        }

        result = EVP_PKEY_decapsulate(ctx, secdec, &seclen, out, outlen);

        if(result != 1){
            printf("decap failed\n");
            result -1;
            goto err;
        }


        if(memcmp(secenc, secdec, seclen) != 0){

            printf("failed to verify\n");

            result = -1;

            goto err;
        }



    } else {

        printf("not default algorithm\n");

        return -2;
    }

err:
    if(key != NULL){

        EVP_PKEY_free(key);
    }
    if(ctx != NULL){
        EVP_PKEY_CTX_free(ctx);
    }

    if(bp_private != NULL){
        BIO_free(bp_private);
    }

    if(bp_public != NULL){
        BIO_free(bp_public);
    }

    if(out != NULL){
        OPENSSL_free(out);
    }
    if(secenc != NULL){
        OPENSSL_free(secenc);
    }
    if(secdec != NULL){
        OPENSSL_free(secdec);
    }

    return result;
}

#define nelem(a) (sizeof(a) / sizeof((a)[0]))

int main(int argc, char *argv[]) {
    size_t i;
    int errcnt = 0, test = 0, query_nocache;
    OSSL_PROVIDER *oqsprov = NULL;
    const OSSL_ALGORITHM *kemalgs;

    T((libctx = OSSL_LIB_CTX_new()) != NULL);


    load_oqs_provider(libctx, "oqsprovider", "oqs.cnf");

    oqsprov = OSSL_PROVIDER_load(libctx, "oqsprovider");

    kemalgs = OSSL_PROVIDER_query_operation(oqsprov, OSSL_OP_KEM, &query_nocache);

    if (kemalgs) {
        for (; kemalgs->algorithm_names != NULL; kemalgs++) {
            if (qs_encdec(kemalgs->algorithm_names)) {
                fprintf(stderr, cGREEN "  KEM test succeeded: %s" cNORM "\n",
                        kemalgs->algorithm_names);
            } else {
                fprintf(stderr, cRED "  KEM test failed: %s" cNORM "\n",
                        kemalgs->algorithm_names);
                ERR_print_errors_fp(stderr);
                errcnt++;
            }
        }
    }



    OSSL_LIB_CTX_free(libctx);

    TEST_ASSERT(errcnt == 0)
    return !test;
}