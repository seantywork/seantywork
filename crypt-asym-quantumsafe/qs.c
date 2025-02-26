

#include "qs_common.h"

static OSSL_LIB_CTX *libctx = NULL;
static OSSL_PROVIDER *oqsprov = NULL;
//static OSSL_LIB_CTX *encodingctx = NULL;
//static OSSL_PROVIDER *encodingprov = NULL;
static char *modulename = NULL;
static char *configfile = NULL;

static char *message = "cryptoinccryptoinccryptoinccryptoinccryptoinccryptoinccryptoinccryptoinccryptoinccryptoinccryptoinccryptoinccryptoinccryptoinccryptoinccryptoinccryptoinccryptoinccryptoinccryptoinc";
static int messagelen = 0;

typedef struct endecode_params_st {
    char *format;
    char *structure;
    char *keytype;
    char *pass;
    int selection;

} ENDECODE_PARAMS;

static ENDECODE_PARAMS plist[] = {
    {"PEM", "PrivateKeyInfo", NULL, NULL,
     OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS},
    {"PEM", "EncryptedPrivateKeyInfo", NULL,
     "Pass the holy handgrenade of antioch",
     OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS},
    {"PEM", "SubjectPublicKeyInfo", NULL, NULL,
     OSSL_KEYMGMT_SELECT_PUBLIC_KEY | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS},
    {"DER", "PrivateKeyInfo", NULL, NULL,
     OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS},
    {"DER", "EncryptedPrivateKeyInfo", NULL,
     "Pass the holy handgrenade of antioch",
     OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS},
    {"DER", "SubjectPublicKeyInfo", NULL, NULL,
     OSSL_KEYMGMT_SELECT_PUBLIC_KEY | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS},
};


static int encode(const EVP_PKEY *pkey) {

    OSSL_ENCODER_CTX *ectx_priv = NULL;
    OSSL_ENCODER_CTX *ectx_pub = NULL;
    BIO *mem_ser = NULL;
    unsigned char *mem_buf = NULL;
    const char *cipher = "AES-256-CBC";
    int ok = -1;

    ectx_priv = OSSL_ENCODER_CTX_new_for_pkey(pkey, plist[0].selection, plist[0].format, plist[0].structure, NULL);

    if (ectx_priv == NULL) {
        printf("No suitable priv encoder found\n");
        goto eend;
    }

    ectx_pub = OSSL_ENCODER_CTX_new_for_pkey(pkey, plist[2].selection, plist[2].format, plist[2].structure, NULL);

    if (ectx_priv == NULL) {
        printf("No suitable pub encoder found\n");
        goto eend;
    }


    /*
    if (pass != NULL) {
        OSSL_ENCODER_CTX_set_passphrase(ectx, (const unsigned char *)pass, strlen(pass));
        OSSL_ENCODER_CTX_set_cipher(ectx, cipher, NULL);
    }
    */

    //mem_ser = BIO_new(BIO_s_mem());
    mem_ser = BIO_new_file("priv.pem", "w");
    if (!OSSL_ENCODER_to_bio(ectx_priv, mem_ser)) {
        printf("encoding priv failed\n");
        goto eend;
    }

    BIO_free_all(mem_ser);

    /*
    BIO_get_mem_data(mem_ser, &mem_buf);
    if (mem_buf == NULL){
        printf("get priv membuf failed\n");
        goto eend;
    }
    */

    //mem_ser = BIO_new(BIO_s_mem());
    mem_ser = BIO_new_file("pub.pem", "w");
    if (!OSSL_ENCODER_to_bio(ectx_pub, mem_ser)) {
        printf("encoding pub failed\n");
        goto eend;
    }

    /*
    BIO_get_mem_data(mem_ser, &mem_buf);
    if (mem_buf == NULL){
        printf("get pub membuf failed\n");
        goto eend;
    }
    */

    ok = 1;

eend:
    BIO_free_all(mem_ser);
    OSSL_ENCODER_CTX_free(ectx_priv);
    OSSL_ENCODER_CTX_free(ectx_pub);
    return ok;
}

static int decode(EVP_PKEY **object) {

    EVP_PKEY *pkey = NULL;
    OSSL_DECODER_CTX *dctx_priv = NULL;
    OSSL_DECODER_CTX *dctx_pub = NULL;
    BIO *priv_bio = NULL;
    BIO *pub_bio = NULL;
    char* encoded[PEM_BUFF_LEN] = {0};
    int encoded_len = 0;

    int ok = 0;

    int rval = read_file_to_buffer(encoded, PEM_BUFF_LEN, "priv.pem");

    if(rval < 1){
        printf("failed to read\n");
        goto dend;
    }

    encoded_len = rval;

    priv_bio = BIO_new_mem_buf(encoded, encoded_len);

    if (priv_bio == NULL){

        printf("get encoded priv bio\n");

        goto dend;
    }

    memset(encoded, 0, PEM_BUFF_LEN);
    
    rval = read_file_to_buffer(encoded, PEM_BUFF_LEN, "pub.pem");

    if(rval < 1){
        printf("failed to read\n");
        goto dend;
    }

    encoded_len = rval;

    pub_bio = BIO_new_mem_buf(encoded, encoded_len);

    if (pub_bio == NULL){

        printf("get encoded pub bio\n");

        goto dend;
    }
    

    dctx_priv = OSSL_DECODER_CTX_new_for_pkey(&pkey, plist[0].format, plist[0].structure, plist[0].keytype, plist[0].selection, libctx, NULL);
    if (dctx_priv == NULL){
        printf("failed to get decode priv ctx\n");
        goto dend;
    }

    dctx_pub = OSSL_DECODER_CTX_new_for_pkey(&pkey, plist[2].format, plist[2].structure, plist[2].keytype, plist[2].selection, libctx, NULL);
    if (dctx_priv == NULL){
        printf("failed to get decode priv ctx\n");
        goto dend;
    }


    if (!OSSL_DECODER_from_bio(dctx_priv, priv_bio)){
        printf("failed to decode priv\n");
        goto dend;
    }

    if (!OSSL_DECODER_from_bio(dctx_pub, pub_bio)){
        printf("failed to decode pub\n");
        goto dend;
    }

    ok = 1;
    *object = pkey;
    pkey = NULL;

dend:
    BIO_free(priv_bio);
    BIO_free(pub_bio);
    OSSL_DECODER_CTX_free(dctx_priv);
    OSSL_DECODER_CTX_free(dctx_pub);
    EVP_PKEY_free(pkey);
    return ok;
}


static int qs_kem(const char *kemalg_name) {
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;
    unsigned char *out = NULL;
    unsigned char *secenc = NULL;
    unsigned char *secdec = NULL;
    size_t outlen, seclen;

    BIO *bp_public = NULL;
    BIO *bp_private = NULL;

    int result = 1;

    if (!alg_is_enabled(kemalg_name)) {
        printf("Not testing disabled algorithm %s.\n", kemalg_name);
        return 0;
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
            result = -1;
            goto err;
        }

        result = EVP_PKEY_CTX_set_params(ctx, NULL);

        if(result != 1){
            printf("set params failed\n");
            result = -1;
            goto err;
        }

        result = EVP_PKEY_keygen(ctx, &key);

        if(result != 1){
            printf("keygen failed\n");
            result = -1;
            goto err;
        }




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
            result = -1;
            goto err;
        }

        secenc = OPENSSL_malloc(seclen);

        if(secenc == NULL){
            printf("malloc secenc failed\n");
            result = -1;
            goto err;
        }

        printf("messagelen: %d outlen: %d seclen: %d\n", messagelen, outlen, seclen);

        for(int i = 0; i < seclen; i++){

            secenc[i] = message[i];
        }


        secdec = OPENSSL_malloc(seclen);

        if(secdec == NULL){
            printf("malloc secdec failed\n");
            result = -1;
            goto err;
        }

        memset(secdec, 0xff, seclen);

        result = EVP_PKEY_encapsulate(ctx, out, &outlen, secenc, &seclen);

        if(result != 1){
            printf("encap run failed\n");
            result = -1;
            goto err;
        }

        result = EVP_PKEY_decapsulate_init(ctx, NULL);

        if(result != 1){
            printf("decap init failed\n");
            result = -1;
            goto err;
        }

        result = EVP_PKEY_decapsulate(ctx, secdec, &seclen, out, outlen);

        if(result != 1){
            printf("decap failed\n");
            result = -1;
            goto err;
        }



        if(memcmp(secenc, secdec, seclen) != 0){

            printf("failed to verify\n");

            result = -1;

            goto err;
        }



    } else {

        printf("not default algorithm\n");

        return 0;
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

    if(result != 1){
        return 0;
    }

    return result;
}

static int qs_signatures(const char *sigalg_name) {
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;
    EVP_PKEY *decoded_key = NULL;

    unsigned char *sig;
    size_t siglen = 0;

    int result = 1;

    if (!alg_is_enabled(sigalg_name)) {
        printf("Not testing disabled algorithm %s.\n", sigalg_name);
        return 0;
    }

    if (OSSL_PROVIDER_available(libctx, "default")) {


        ctx = EVP_PKEY_CTX_new_from_name(libctx, sigalg_name, OQSPROV_PROPQ);

        if (ctx == NULL){

            printf("ctx is null\n");

            result = -1;

            goto err;

        }

        result = EVP_PKEY_keygen_init(ctx); 

        if(result != 1){
            printf("keygen init failed\n");
            result = -1;
            goto err;
        }

        result = EVP_PKEY_CTX_set_params(ctx, NULL);

        if(result != 1){
            printf("set params failed\n");
            result = -1;
            goto err;
        }

        result = EVP_PKEY_keygen(ctx, &key);

        if(result != 1){
            printf("keygen failed\n");
            result = -1;
            goto err;
        }

        result = encode(key);

        if(result != 1){
            printf("encode failed\n");
            result = -1;
            goto err;
        }

        /*
        result = decode(&decoded_key);

        if(result != 1){
            printf("decode failed\n");
            result = -1;
            goto err;
        }

        */
        mdctx = EVP_MD_CTX_new();

        if(mdctx == NULL){

            printf("md ctx failed\n");
            result = -1;
            goto err;
        }

        result = EVP_DigestSignInit_ex(mdctx, NULL, "SHA512", libctx, NULL, key, NULL);

        if(result != 1){

            printf("sing init failed\n");
            result = -1;
            goto err;
        }

        result = EVP_DigestSignUpdate(mdctx, message, sizeof(message));

        if(result != 1){
            printf("sign update failed\n");
            result = -1;
            goto err;
        }

        result = EVP_DigestSignFinal(mdctx, NULL, &siglen);

        if(result != 1){

            printf("sign final 1 failed\n");
            result = -1;
            goto err;
        }

        sig = OPENSSL_malloc(siglen);

        if(sig == NULL){

            printf("sig failed\n");
            result = -1;
            goto err;
        }

        result = EVP_DigestSignFinal(mdctx, sig, &siglen);

        if(result != 1){
            printf("sign final 2 failed\n");
            result = -1;
            goto err;
        }

        result = EVP_DigestVerifyInit_ex(mdctx, NULL, "SHA512", libctx, NULL, key, NULL);

        if(result != 1){
            printf("verify init failed\n");
            result = -1;
            goto err;
        }

        result = EVP_DigestVerifyUpdate(mdctx, message, sizeof(message));

        if(result != 1){

            printf("verify update failed\n");
            result = -1;
            goto err;
        }

        result = EVP_DigestVerifyFinal(mdctx, sig, siglen);

        if(result != 1){

            printf("verify final\n");
            result = -1;
            goto err;
        }
    }


err:
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    OPENSSL_free(sig);

    if(result < 0){
        return 0;
    }

    return result;
}


#define nelem(a) (sizeof(a) / sizeof((a)[0]))

int main(int argc, char *argv[]) {
    size_t i;
    int errcnt = 0, test = 0, query_nocache;

    const OSSL_ALGORITHM *kemalgs;
    const OSSL_ALGORITHM *sigalgs;

    //T((encodingctx = OSSL_LIB_CTX_new()) != NULL);
    T((libctx = OSSL_LIB_CTX_new()) != NULL);

    messagelen = strlen(message);

    //load_oqs_provider(encodingctx, "default", "oqs.cnf");
    load_oqs_provider(libctx, "oqsprovider", "oqs.cnf");

    //encodingprov = OSSL_PROVIDER_load(encodingctx, "default");
    oqsprov = OSSL_PROVIDER_load(libctx, "oqsprovider");


    kemalgs = OSSL_PROVIDER_query_operation(oqsprov, OSSL_OP_KEM, &query_nocache);

    if (kemalgs) {
        for (; kemalgs->algorithm_names != NULL; kemalgs++) {
            if (qs_kem(kemalgs->algorithm_names)) {
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

    sigalgs = OSSL_PROVIDER_query_operation(oqsprov, OSSL_OP_SIGNATURE, &query_nocache);

    if (sigalgs) {
        for (; sigalgs->algorithm_names != NULL; sigalgs++) {
            if (qs_signatures(sigalgs->algorithm_names)) {
                fprintf(stderr, cGREEN "  Signature test succeeded: %s" cNORM "\n", sigalgs->algorithm_names);
            } else {
                fprintf(stderr, cRED "  Signature test failed: %s" cNORM "\n", sigalgs->algorithm_names);
                ERR_print_errors_fp(stderr);
                errcnt++;
            }
        }
    }


    //OSSL_LIB_CTX_free(encodingctx);
    OSSL_LIB_CTX_free(libctx);

    TEST_ASSERT(errcnt == 0);
    return !test;
}