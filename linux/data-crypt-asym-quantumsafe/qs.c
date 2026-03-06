

#include "qs_common.h"
#include "qs_tls.h"

FILE* logfile = NULL;
static OSSL_LIB_CTX *libctx = NULL;
static OSSL_PROVIDER *defaultprov = NULL;
static OSSL_PROVIDER *oqsprov = NULL;
static OSSL_PROVIDER *fibsprov = NULL;
//static OSSL_LIB_CTX *encodingctx = NULL;
//static OSSL_PROVIDER *encodingprov = NULL;
static char *modulename = NULL;
static char *configfile = NULL;
const OSSL_ALGORITHM *kemalgs;
const OSSL_ALGORITHM *sigalgs;

static char *message = "asdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdf";
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

static EVP_PKEY * encodedecode(const EVP_PKEY *pkey){

    OSSL_ENCODER_CTX *ectx_priv = NULL;
    OSSL_ENCODER_CTX *ectx_pub = NULL;
    BIO *mem_ser_priv = NULL;
    BIO *mem_ser_pub = NULL;
    BUF_MEM *mem_buf_priv = NULL;
    BUF_MEM *mem_buf_pub = NULL;
    const char *cipher = "AES-256-CBC";
    int ok = 0;

    OSSL_DECODER_CTX *dctx_priv = NULL;
    OSSL_DECODER_CTX *dctx_pub = NULL;
    BIO *priv_bio = NULL;
    BIO *pub_bio = NULL;

    EVP_PKEY *newpkey = EVP_PKEY_new();

    ectx_priv = OSSL_ENCODER_CTX_new_for_pkey(pkey, plist[0].selection, plist[0].format, plist[0].structure, NULL);

    if (ectx_priv == NULL) {
        printf("No suitable priv encoder found\n");
        goto edend;
    }

    ectx_pub = OSSL_ENCODER_CTX_new_for_pkey(pkey, plist[2].selection, plist[2].format, plist[2].structure, NULL);

    if (ectx_pub == NULL) {
        printf("No suitable pub encoder found\n");
        goto edend;
    }


    /*
    if (pass != NULL) {
        OSSL_ENCODER_CTX_set_passphrase(ectx, (const unsigned char *)pass, strlen(pass));
        OSSL_ENCODER_CTX_set_cipher(ectx, cipher, NULL);
    }
    */

    mem_ser_priv = BIO_new(BIO_s_mem());
    //mem_ser = BIO_new_file("priv.pem", "w");
    if (!OSSL_ENCODER_to_bio(ectx_priv, mem_ser_priv)) {
        printf("encoding priv failed\n");
        goto edend;
    }

    
    BIO_get_mem_ptr(mem_ser_priv, &mem_buf_priv);
    if (mem_buf_priv == NULL){
        printf("get priv membuf failed\n");
        goto edend;
    }

    mem_ser_pub = BIO_new(BIO_s_mem());
    //mem_ser = BIO_new_file("pub.pem", "w");
    if (!OSSL_ENCODER_to_bio(ectx_pub, mem_ser_pub)) {
        printf("encoding pub failed\n");
        goto edend;
    }

    
    BIO_get_mem_ptr(mem_ser_pub, &mem_buf_pub);
    if (mem_buf_pub == NULL){
        printf("get pub membuf failed\n");
        goto edend;
    }
    
    priv_bio = BIO_new_mem_buf(mem_buf_priv->data, mem_buf_priv->length);

    if (priv_bio == NULL){

        printf("get encoded priv bio\n");

        goto edend;
    }

    pub_bio = BIO_new_mem_buf(mem_buf_pub->data, mem_buf_pub->length);

    if (pub_bio == NULL){

        printf("get encoded pub bio\n");

        goto edend;
    }

    dctx_priv = OSSL_DECODER_CTX_new_for_pkey(&newpkey, plist[0].format, plist[0].structure, plist[0].keytype, plist[0].selection, libctx, NULL);
    if (dctx_priv == NULL){
        printf("failed to get decode priv ctx\n");
        goto edend;
    }

    
    dctx_pub = OSSL_DECODER_CTX_new_for_pkey(&newpkey, plist[2].format, plist[2].structure, plist[2].keytype, plist[2].selection, libctx, NULL);
    if (dctx_pub == NULL){
        printf("failed to get decode priv ctx\n");
        goto edend;
    }

    

    if (!OSSL_DECODER_from_bio(dctx_priv, priv_bio)){
        printf("failed to decode priv\n");
        goto edend;
    }

    
    if (!OSSL_DECODER_from_bio(dctx_pub, pub_bio)){
        printf("failed to decode pub\n");
        goto edend;
    }
    

    //*object = newpkey;
    //newpkey = NULL;
    ok = 1;

edend:
    if(mem_ser_priv != NULL){
        BIO_free_all(mem_ser_priv);
    }
    if(mem_ser_pub != NULL){
        BIO_free_all(mem_ser_pub);
    }
    if(ectx_priv != NULL){
        OSSL_ENCODER_CTX_free(ectx_priv);
    }
    if(ectx_pub != NULL){
        OSSL_ENCODER_CTX_free(ectx_pub);
    }
    if(priv_bio != NULL){
        BIO_free(priv_bio);
    }
    if(pub_bio != NULL){
        BIO_free(pub_bio);
    }
    if(dctx_priv != NULL){
        OSSL_DECODER_CTX_free(dctx_priv);
    }
    if(dctx_pub != NULL){
        OSSL_DECODER_CTX_free(dctx_pub);
    }
    //if(newpkey != NULL){
    //    EVP_PKEY_free(newpkey);
    //}

    if(ok != 1){

        return NULL;
    }

    return newpkey;

}



static EVP_PKEY * encodedecodepub(const EVP_PKEY *pkey){

    OSSL_ENCODER_CTX *ectx_priv = NULL;
    OSSL_ENCODER_CTX *ectx_pub = NULL;
    BIO *mem_ser_priv = NULL;
    BIO *mem_ser_pub = NULL;
    BUF_MEM *mem_buf_priv = NULL;
    BUF_MEM *mem_buf_pub = NULL;
    const char *cipher = "AES-256-CBC";
    int ok = 0;

    OSSL_DECODER_CTX *dctx_priv = NULL;
    OSSL_DECODER_CTX *dctx_pub = NULL;
    BIO *priv_bio = NULL;
    BIO *pub_bio = NULL;

    EVP_PKEY *newpkey = EVP_PKEY_new();

    ectx_priv = OSSL_ENCODER_CTX_new_for_pkey(pkey, plist[0].selection, plist[0].format, plist[0].structure, NULL);

    if (ectx_priv == NULL) {
        printf("No suitable priv encoder found\n");
        goto edend;
    }

    ectx_pub = OSSL_ENCODER_CTX_new_for_pkey(pkey, plist[2].selection, plist[2].format, plist[2].structure, NULL);

    if (ectx_pub == NULL) {
        printf("No suitable pub encoder found\n");
        goto edend;
    }


    /*
    if (pass != NULL) {
        OSSL_ENCODER_CTX_set_passphrase(ectx, (const unsigned char *)pass, strlen(pass));
        OSSL_ENCODER_CTX_set_cipher(ectx, cipher, NULL);
    }
    */

    mem_ser_priv = BIO_new(BIO_s_mem());
    //mem_ser = BIO_new_file("priv.pem", "w");
    if (!OSSL_ENCODER_to_bio(ectx_priv, mem_ser_priv)) {
        printf("encoding priv failed\n");
        goto edend;
    }

    
    BIO_get_mem_ptr(mem_ser_priv, &mem_buf_priv);
    if (mem_buf_priv == NULL){
        printf("get priv membuf failed\n");
        goto edend;
    }

    mem_ser_pub = BIO_new(BIO_s_mem());
    //mem_ser = BIO_new_file("pub.pem", "w");
    if (!OSSL_ENCODER_to_bio(ectx_pub, mem_ser_pub)) {
        printf("encoding pub failed\n");
        goto edend;
    }

    
    BIO_get_mem_ptr(mem_ser_pub, &mem_buf_pub);
    if (mem_buf_pub == NULL){
        printf("get pub membuf failed\n");
        goto edend;
    }
    /*
    priv_bio = BIO_new_mem_buf(mem_buf_priv->data, mem_buf_priv->length);

    if (priv_bio == NULL){

        printf("get encoded priv bio\n");

        goto edend;
    }

    */
    pub_bio = BIO_new_mem_buf(mem_buf_pub->data, mem_buf_pub->length);

    if (pub_bio == NULL){

        printf("get encoded pub bio\n");

        goto edend;
    }

    /*
    dctx_priv = OSSL_DECODER_CTX_new_for_pkey(&newpkey, plist[0].format, plist[0].structure, plist[0].keytype, plist[0].selection, libctx, NULL);
    if (dctx_priv == NULL){
        printf("failed to get decode priv ctx\n");
        goto edend;
    }

    */
    
    dctx_pub = OSSL_DECODER_CTX_new_for_pkey(&newpkey, plist[2].format, plist[2].structure, plist[2].keytype, plist[2].selection, libctx, NULL);
    if (dctx_pub == NULL){
        printf("failed to get decode priv ctx\n");
        goto edend;
    }

    /*

    if (!OSSL_DECODER_from_bio(dctx_priv, priv_bio)){
        printf("failed to decode priv\n");
        goto edend;
    }

    */
    
    if (!OSSL_DECODER_from_bio(dctx_pub, pub_bio)){
        printf("failed to decode pub\n");
        goto edend;
    }
    

    //*object = newpkey;
    //newpkey = NULL;
    ok = 1;

edend:
    if(mem_ser_priv != NULL){
        BIO_free_all(mem_ser_priv);
    }
    if(mem_ser_pub != NULL){
        BIO_free_all(mem_ser_pub);
    }
    if(ectx_priv != NULL){
        OSSL_ENCODER_CTX_free(ectx_priv);
    }
    if(ectx_pub != NULL){
        OSSL_ENCODER_CTX_free(ectx_pub);
    }
    if(priv_bio != NULL){
        BIO_free(priv_bio);
    }
    if(pub_bio != NULL){
        BIO_free(pub_bio);
    }
    if(dctx_priv != NULL){
        OSSL_DECODER_CTX_free(dctx_priv);
    }
    if(dctx_pub != NULL){
        OSSL_DECODER_CTX_free(dctx_pub);
    }
    //if(newpkey != NULL){
    //    EVP_PKEY_free(newpkey);
    //}

    if(ok != 1){

        return NULL;
    }

    return newpkey;

}

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

    int rval = read_file_to_buffer((uint8_t*)encoded, PEM_BUFF_LEN, "priv.pem");

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
    
    rval = read_file_to_buffer((uint8_t*)encoded, PEM_BUFF_LEN, "pub.pem");

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


static void cleanup_heap(uint8_t *secret_key, uint8_t *shared_secret_e,
    uint8_t *shared_secret_d, uint8_t *public_key,
    uint8_t *ciphertext, OQS_KEM *kem) {
    if (kem != NULL) {
        OQS_MEM_secure_free(secret_key, kem->length_secret_key);
        OQS_MEM_secure_free(shared_secret_e, kem->length_shared_secret);
        OQS_MEM_secure_free(shared_secret_d, kem->length_shared_secret);
    }
    OQS_MEM_insecure_free(public_key);
    OQS_MEM_insecure_free(ciphertext);
    OQS_KEM_free(kem);
}


static void cleanup_heap_sig(uint8_t *public_key, uint8_t *secret_key, uint8_t *signature, OQS_SIG *sig) {
    if (sig != NULL) {
        OQS_MEM_secure_free(secret_key, sig->length_secret_key);

    }
    OQS_MEM_insecure_free(public_key);
    OQS_MEM_insecure_free(signature);
    OQS_SIG_free(sig);
}



static int qs_kem(){

	OQS_KEM *kem = NULL;
	uint8_t *public_key = NULL;
	uint8_t *secret_key = NULL;
	uint8_t *ciphertext = NULL;
	uint8_t *shared_secret_e = NULL;
	uint8_t *shared_secret_d = NULL;


	kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
	if (kem == NULL) {
		printf("[example_heap]  OQS_KEM_kyber_768 was not enabled at "
		       "compile-time.\n");
		return OQS_SUCCESS;
	}

	public_key = OQS_MEM_malloc(kem->length_public_key);
	secret_key = OQS_MEM_malloc(kem->length_secret_key);
	ciphertext = OQS_MEM_malloc(kem->length_ciphertext);
	shared_secret_e = OQS_MEM_malloc(kem->length_shared_secret);
	shared_secret_d = OQS_MEM_malloc(kem->length_shared_secret);
	if ((public_key == NULL) || (secret_key == NULL) || (ciphertext == NULL) ||
	        (shared_secret_e == NULL) || (shared_secret_d == NULL)) {
		fprintf(stderr, "ERROR: OQS_MEM_malloc failed!\n");
		cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key,
		             ciphertext, kem);

		return OQS_ERROR;
	}

    messagelen = strlen(message);

    printf("messagelen: %d, ciphertext len: %d\n", messagelen, kem->length_ciphertext);

    memcpy(ciphertext, message,kem->length_ciphertext);

    memset(shared_secret_e, 0, kem->length_shared_secret);

    memset(shared_secret_d, 0, kem->length_shared_secret);

    printf("shared secret e: length: %d: ", kem->length_shared_secret);

    for (int i = 0 ; i < kem->length_shared_secret; i++){


        printf("%02X", shared_secret_e[i]);

    }

    printf("\n");

    printf("shared secret d: length: %d: ", kem->length_shared_secret);

    for (int i = 0 ; i < kem->length_shared_secret; i++){


        printf("%02X", shared_secret_d[i]);

    }

    printf("\n");

	OQS_STATUS rc = OQS_KEM_keypair(kem, public_key, secret_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_keypair failed!\n");
		cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key,
		             ciphertext, kem);

		return OQS_ERROR;
	}


	rc = OQS_KEM_encaps(kem, ciphertext, shared_secret_e, public_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_encaps failed!\n");
		cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key,
		             ciphertext, kem);

		return OQS_ERROR;
	}

	rc = OQS_KEM_decaps(kem, shared_secret_d, ciphertext, secret_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_decaps failed!\n");
		cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key,
		             ciphertext, kem);

		return OQS_ERROR;
	}

    rc = memcmp(shared_secret_d, shared_secret_e, kem->length_shared_secret);

    if(rc != 0){
		fprintf(stderr, "ERROR: memcmp failed\n");
		cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key,
		             ciphertext, kem);

		return OQS_ERROR;

    }


    printf("shared secret e: %d: ", kem->length_shared_secret);

    for (int i = 0 ; i < kem->length_shared_secret; i++){


        printf("%02X", shared_secret_e[i]);

    }

    printf("\n");

    printf("shared secret d: %d: ", kem->length_shared_secret);

    for (int i = 0 ; i < kem->length_shared_secret; i++){


        printf("%02X", shared_secret_d[i]);

    }

    printf("\n");

	printf("operations completed.\n");
	cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key,
	             ciphertext, kem);

	return OQS_SUCCESS; // success

}


static int qs_signatures() {

	OQS_SIG *sig = NULL;
	uint8_t *public_key = NULL;
	uint8_t *secret_key = NULL;

	uint8_t *signature = NULL;
	size_t signature_len;
	OQS_STATUS rc;

	sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
	if (sig == NULL) {
		printf("OQS_SIG_alg_ml_dsa_65 was not enabled at compile-time.\n");
		return OQS_ERROR;
	}

	public_key = OQS_MEM_malloc(sig->length_public_key);
	secret_key = OQS_MEM_malloc(sig->length_secret_key);

	signature = OQS_MEM_malloc(sig->length_signature);
	if ((public_key == NULL) || (secret_key == NULL) || (signature == NULL)) {
		fprintf(stderr, "ERROR: OQS_MEM_malloc failed!\n");
		cleanup_heap_sig(public_key, secret_key, signature, sig);
		return OQS_ERROR;
	}


	rc = OQS_SIG_keypair(sig, public_key, secret_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_keypair failed!\n");
		cleanup_heap_sig(public_key, secret_key, signature, sig);
		return OQS_ERROR;
	}
	rc = OQS_SIG_sign(sig, signature, &signature_len, message, messagelen, secret_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_sign failed!\n");
		cleanup_heap_sig(public_key, secret_key, signature, sig);
		return OQS_ERROR;
	}

    printf("signature: ");
    for (int i = 0; i < signature_len; i++){

        printf("%02X", signature[i]);
    }
    printf("\n");
	rc = OQS_SIG_verify(sig, message, messagelen, signature, signature_len, public_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_verify failed!\n");
		cleanup_heap_sig(public_key, secret_key, signature, sig);
		return OQS_ERROR;
	}

	printf("operations completed.\n");
	cleanup_heap_sig(public_key, secret_key, signature, sig);
	return OQS_SUCCESS; // success

}


static int sig_verify(BIO* cert_pem, BIO* intermediate_pem)
{
    //BIO *b = BIO_new(BIO_s_mem());
    //BIO_puts(b, intermediate_pem);

    BIO* b = intermediate_pem;
    X509 * issuer = PEM_read_bio_X509(b, NULL, NULL, NULL);
    EVP_PKEY *signing_key=X509_get_pubkey(issuer);

    //BIO *c = BIO_new(BIO_s_mem());
    //BIO_puts(c, cert_pem);
    BIO* c = cert_pem;
    X509 * x509 = PEM_read_bio_X509(c, NULL, NULL, NULL);
    
    int result = X509_verify(x509, signing_key);
    

    EVP_PKEY_free(signing_key);
    X509_free(x509);
    X509_free(issuer);
 
    return result;
}

static int cert_verify(){

    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests(); 

    BIO* cert = NULL;
    BIO* intermediate = NULL;


    cert = BIO_new(BIO_s_file());

    intermediate = BIO_new(BIO_s_file());

    int ret = BIO_read_filename(cert, "./srv.crt.pem");

    ret = BIO_read_filename(intermediate, "./ca.crt.pem");

    //cert_info(cert);
    //cert_info(intermediate);
    int res = sig_verify(cert,intermediate);
    printf("result: %d\n",res);


    BIO_free_all(cert);
    BIO_free_all(intermediate);

    return res;

}




static int qs_tlsnet(const char *sig_name, const char *kem_name, int dtls_flag) {
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int ret = 1, testresult = 0;
    char group[1024] = {0};
    char certpath_ca[300];
    char certpath_c[300];
    char privkeypath_c[300];
    char certpath[300];
    char privkeypath[300];
    char *certsdir = "certs";
#ifndef OPENSSL_SYS_VMS
    const char *sep = "/";
#else
    const char *sep = "";
#endif


    sprintf(group, "sig: %s, kem: %s\n", sig_name, kem_name);
    
    fputs(group, logfile);

    sprintf(certpath_ca, "%s%s%s%s", certsdir, sep, sig_name, "_ca.crt");
    sprintf(certpath_c, "%s%s%s%s", certsdir, sep, sig_name, "_cli.crt");
    sprintf(privkeypath_c, "%s%s%s%s", certsdir, sep, sig_name, "_cli.key");
    sprintf(certpath, "%s%s%s%s", certsdir, sep, sig_name, "_srv.crt");
    sprintf(privkeypath, "%s%s%s%s", certsdir, sep, sig_name, "_srv.key");
    /* ensure certsdir exists */
    if (mkdir(certsdir, 0700)) {
        if (errno != EEXIST) {
            fprintf(stderr, "Couldn't create certsdir %s: Err = %d\n", certsdir,
                    errno);
            ret = -1;
            goto err;
        }
    }
    if (!create_cert_key(libctx, (char *)sig_name, certpath_ca, certpath_c, privkeypath_c, certpath, privkeypath)) {
        fprintf(stderr, "Cert/keygen failed for %s at %s/%s\n", sig_name,
                certpath, privkeypath);
        ret = -1;
        goto err;
    }

    testresult = create_tls1_3_ctx_pair(libctx, &sctx, &cctx, certpath_ca, certpath_c, privkeypath_c, 
                            certpath, privkeypath, dtls_flag);

    if (!testresult) {
        ret = -1;
        goto err;
    }


    serverssl = SSL_new(sctx);
    clientssl = SSL_new(cctx);

    testresult = SSL_set1_groups_list(serverssl, kem_name);

    if (!testresult) {
        ret = -5;
        goto err;
    }
    testresult = SSL_set1_groups_list(clientssl, kem_name);

    if (!testresult) {
        ret = -5;
        goto err;
    }

    testresult = create_tls_connection(serverssl, clientssl, SSL_ERROR_NONE);
    if (!testresult) {
        ret = -5;
        goto err;
    }


err:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return ret;
}




#define nelem(a) (sizeof(a) / sizeof((a)[0]))

int main(int argc, char *argv[]) {
    size_t i;
    int errcnt = 0, test = 0, query_nocache;


    //T((encodingctx = OSSL_LIB_CTX_new()) != NULL);
    T((libctx = OSSL_LIB_CTX_new()) != NULL);

    messagelen = strlen(message);

     if(strcmp(argv[1], "kem") == 0){

        if (qs_kem() == OQS_SUCCESS) {
            fprintf(stderr, cGREEN "  KEM test succeeded" cNORM "\n");
        } else {
            fprintf(stderr, cRED "  KEM test failed" cNORM "\n");
            ERR_print_errors_fp(stderr);
            errcnt++;
        }

    } else if (strcmp(argv[1], "sig") == 0){

            
        if ( qs_signatures() == OQS_SUCCESS) {

            fprintf(stderr, cGREEN "sig test succeeded" cNORM "\n");

        } else {

            errcnt += 1;

            fprintf(stderr, cRED "sig test failed" cNORM "\n");

        }

    } else if (strcmp(argv[1], "cert") == 0){

        if ( cert_verify() == 1) {

            fprintf(stderr, cGREEN "cert test succeeded" cNORM "\n");

        } else {

            errcnt += 1;

            fprintf(stderr, cRED "cert test failed" cNORM "\n");

        }

    } else if (strcmp(argv[1], "tls") == 0){

        logfile = fopen("log.txt", "w");

#ifdef OSSL_CAPABILITY_TLS_SIGALG_NAME

        int res = qs_tlsnet(THIS_SIG_NAME, THIS_KEM_NAME, 0);
            
        if (res == 1) {

            fprintf(stderr, cGREEN "tls net test succeeded" cNORM "\n");

        } else {

            errcnt += 1;

            fprintf(stderr, cRED "tls net test failed" cNORM "\n");

        }
#else
        fprintf(stderr,
                "TLS-SIG handshake test not enabled. Update OpenSSL to more "
                "current version.\n");
#endif
    }



    //OSSL_LIB_CTX_free(encodingctx);
    OSSL_LIB_CTX_free(libctx);

    TEST_ASSERT(errcnt == 0);
    return !test;
}