#include "qs.h"
#include "qs_tls.h"

/*
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
*/
int qs_key_create(){
    SSL_CTX *cctx = NULL, *sctx = NULL;
    int ret = 1, testresult = 0;

    if (!create_key(libctx, (char *)sig_name, keypath_ca, pubpath_ca, keypath_c, pubpath_c, keypath, pubpath)) {
        fprintf(stderr, "Cert/keygen failed for %s\n", sig_name);
        ret = -1;
        goto err;
    }
    if (!create_key(libctx, (char *)kem_name, kem_keypath_ca, kem_pubpath_ca, kem_keypath_c, kem_pubpath_c, kem_keypath, kem_pubpath)) {
        fprintf(stderr, "Cert/keygen failed for %s\n", kem_name);
        ret = -1;
        goto err;
    }
err:
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return ret;
}


int qs_encap(char* enc_msg_path, char* sec_path){

    int result = -1;

    FILE* fp;
    EVP_PKEY* pub_key = NULL;
    EVP_PKEY_CTX* ctx = NULL;
    char enc_msg[8192] = {0};
    char sec_msg[8192] = {0};
    size_t enc_len = 0;
    size_t sec_len = 0;
    char* err;
    unsigned char* enc_hex = NULL;
    unsigned char* sec_hex = NULL;

    fp = fopen(kem_pubpath, "r");
    pub_key = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    ctx = EVP_PKEY_CTX_new(pub_key, NULL);  
    if(EVP_PKEY_encapsulate_init(ctx, NULL) != 1){
        printf("encap init failed\n");
        goto out;
    }
    if(EVP_PKEY_CTX_set_kem_op(ctx, kem_name) != 1){
        printf("encap set op failed\n");
        goto out;
    }
    if(EVP_PKEY_encapsulate(ctx, NULL, &enc_len, NULL, &sec_len) != 1){
        printf("encap get len failed\n");
        goto out; 
    }
    printf("enclen: %d, seclen: %d\n", enc_len, sec_len);
    if(EVP_PKEY_encapsulate(ctx, enc_msg, &enc_len, sec_msg, &sec_len) != 1){
        printf("encap failed\n");
        goto out;
    }
    enc_hex = char2hex(enc_len, (unsigned char*)enc_msg);
    printf("enclen: %d\n", enc_len);
    fp = fopen(enc_msg_path, "w");
    fputs((char*)enc_hex, fp);
    fclose(fp);
    sec_hex = char2hex(sec_len, (unsigned char*)sec_msg);
    printf("seclen: %d\n", sec_len);
    fp = fopen(sec_path, "w");
    fputs((char*)sec_hex, fp);
    fclose(fp);
    result = 1;
out:
    if(pub_key != NULL){
        EVP_PKEY_free(pub_key);
    }
    if(ctx != NULL){
        EVP_PKEY_CTX_free(ctx);
    }
    if(enc_hex != NULL){
        free(enc_hex);
    }
    if(sec_hex != NULL){
        free(sec_hex);
    }
    return result;
}

int qs_decap(char* enc_msg_path, char* sec_path){

    int result = -1;
    FILE* fp;
    EVP_PKEY* priv_key = NULL;
    EVP_PKEY_CTX* ctx = NULL;
    char sec_msg[8192] = {0};
    size_t sec_len = 8192;
    char peer_sec_msg[8192] = {0};
    size_t peer_sec_len = 8192;
    char peer_enc_msg[8192] = {0};
    int peer_enc_len = 8192;
    char* err;
    unsigned char* peer_sec_bin = NULL;
    unsigned char* peer_enc_bin = NULL;

    fp = fopen(kem_keypath, "r");
    priv_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    fp = fopen(sec_path, "r");
    fgets(peer_sec_msg, peer_sec_len, fp);
    fclose(fp);
    peer_sec_bin = hex2char((unsigned char*)peer_sec_msg);
    peer_sec_len = strlen(peer_sec_msg) / 2;
    fp = fopen(enc_msg_path, "r");
    fgets(peer_enc_msg, peer_enc_len, fp);
    fclose(fp);
    peer_enc_bin = hex2char((unsigned char*)peer_enc_msg);
    peer_enc_len = strlen(peer_enc_msg) / 2;
    ctx = EVP_PKEY_CTX_new(priv_key, NULL);
    if(!EVP_PKEY_decapsulate_init(ctx, NULL)){
        printf("decap init failed\n");
        goto out;
    }
    if(EVP_PKEY_CTX_set_kem_op(ctx, kem_name) != 1){
        printf("decap set op failed\n");
        goto out;
    }
    if(EVP_PKEY_decapsulate(ctx, NULL, &sec_len, peer_enc_bin, peer_enc_len) != 1){
        printf("decap getlen failed\n");
        goto out;
    }
    printf("seclen: %d\n", sec_len);
    if(EVP_PKEY_decapsulate(ctx, sec_msg, &sec_len, peer_enc_bin, peer_enc_len) != 1){
        printf("decap failed\n");
        goto out;
    }
    if(memcmp(sec_msg, peer_sec_bin, sec_len) != 0){
        printf("memcmp failed\n");
        goto out;
    }
    result = 1;
out:
    if(priv_key != NULL){
        EVP_PKEY_free(priv_key);
    }
    if(ctx != NULL){
        EVP_PKEY_CTX_free(ctx);
    }
    if(peer_sec_bin != NULL){
        free(peer_sec_bin);
    }
    if(peer_enc_bin != NULL){
        free(peer_enc_bin);
    }
    return result;
}


int qs_signature(){

    int result = -1;
    FILE* fp;
    EVP_SIGNATURE *sig_alg = NULL;
    EVP_PKEY_CTX* ctx_sign = NULL;
    EVP_PKEY_CTX* ctx_verify = NULL;
    EVP_PKEY* pkey = NULL;
    EVP_PKEY* pub_key = NULL;
    unsigned char *sig = NULL;
    unsigned char* hash = NULL;
    size_t siglen;
    // sha256 "hello"
    char* hashstr = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";


    fp = fopen(keypath, "r");

    pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    fp = fopen(pubpath, "r");
    pub_key = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);

    ctx_sign = EVP_PKEY_CTX_new(pkey, NULL);
    if(ctx_sign == NULL){
		printf("ctx sign failed\n");
        goto out;
    }
    ctx_verify = EVP_PKEY_CTX_new(pub_key, NULL);
    if(ctx_verify == NULL){
		printf("ctx verify failed\n");
        goto out;
    }

    int hash_length = strlen(hashstr);
    hash_length = hash_length / 2;

    hash = hex2char(hashstr);
    sig_alg = EVP_SIGNATURE_fetch(NULL, sig_name, NULL);

    if (EVP_PKEY_sign_message_init(ctx_sign, sig_alg, NULL) != 1){
		printf("signature init failed\n");
        goto out;
    }

    if (EVP_PKEY_sign(ctx_sign, NULL, &siglen, hash, hash_length) != 1){
		printf("signature prepare failed\n");
        goto out;
    }

    sig = malloc(siglen);
    if (sig == NULL){
		printf("signature malloc failed\n");
        goto out;
    }
    memset(sig, 0, siglen);
    if (EVP_PKEY_sign(ctx_sign, sig, &siglen, hash, hash_length) != 1){
		printf("signature sign failed\n");
        goto out;
    }
    printf("signed: siglen: %d, hashlen: %d\n", siglen, hash_length);
    if (EVP_PKEY_verify_message_init(ctx_verify, sig_alg, NULL) <= 0){
		printf("signature verify init failed\n");
        goto out;
    }

    int ret = EVP_PKEY_verify(ctx_verify, sig, siglen, hash, hash_length);

    printf("result: %d\n", ret);
    result = ret;
out:
    if(pkey != NULL){
        EVP_PKEY_free(pkey);
    }
    if(pub_key != NULL){
        EVP_PKEY_free(pub_key);
    }
    if(sig_alg != NULL){
        EVP_SIGNATURE_free(sig_alg);
    }
    if(ctx_sign != NULL){
        EVP_PKEY_CTX_free(ctx_sign);
    }
    if(ctx_verify != NULL){
        EVP_PKEY_CTX_free(ctx_verify);
    }
    if(sig != NULL){
        free(sig);
    }
    if(hash != NULL){
        free(hash);
    }
    return result;
}

/*
int oqs_kem(){

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

    for(int i = 0; i < kem->length_ciphertext; i++){
        int idx = i % messagelen;
        ciphertext[i] = message[idx];
    }

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

    printf("ciphertext before encap: ");

    for (int i = 0 ; i < kem->length_ciphertext; i++){

        printf("%02X", ciphertext[i]);

    }

    printf("\n");

	rc = OQS_KEM_encaps(kem, ciphertext, shared_secret_e, public_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_encaps failed!\n");
		cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key,
		             ciphertext, kem);

		return OQS_ERROR;
	}

    printf("ciphertext after encap: ");

    for (int i = 0 ; i < kem->length_ciphertext; i++){

        printf("%02X", ciphertext[i]);

    }

    printf("\n");

	rc = OQS_KEM_decaps(kem, shared_secret_d, ciphertext, secret_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_decaps failed!\n");
		cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key,
		             ciphertext, kem);

		return OQS_ERROR;
	}

    printf("ciphertext after decap: ");

    for (int i = 0 ; i < kem->length_ciphertext; i++){

        printf("%02X", ciphertext[i]);

    }

    printf("\n");

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


int oqs_signature() {

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

*/



int qs_cert_create(){
    SSL_CTX *cctx = NULL, *sctx = NULL;
    int ret = 1, testresult = 0;
    if (!create_cert(libctx, (char *)sig_name, certpath_ca, keypath_ca, pubpath_ca, certpath_c, pubpath_c, certpath, pubpath)) {
        fprintf(stderr, "cert failed for %s\n", sig_name);
        ret = -1;
        goto err;
    }
err:
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return ret;
}

static int sig_verify(BIO* cert_pem, BIO* intermediate_pem){
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

int qs_cert_verify(){

    int ret = 1, testresult = 0;

    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests(); 

    BIO* cert = NULL;
    BIO* intermediate = NULL;


    cert = BIO_new(BIO_s_file());

    intermediate = BIO_new(BIO_s_file());

    ret = BIO_read_filename(cert, certpath);

    ret = BIO_read_filename(intermediate, certpath_ca);

    //cert_info(cert);
    //cert_info(intermediate);
    int res = sig_verify(cert,intermediate);
    printf("result: %d\n",res);
    BIO_free_all(cert);
    BIO_free_all(intermediate);

    return res;

}



int qs_tlsnet(const char *sig_name, const char *kem_name, int dtls_flag) {
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int ret = 1, testresult = 0;

    testresult = create_tls1_3_ctx_pair(libctx, &sctx, &cctx, certpath_ca, certpath_c, keypath_c, 
                            certpath, keypath, dtls_flag);

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

