

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


static int key_create(){
    char *sig_name = THIS_SIG_NAME;
    char *kem_name = THIS_KEM_NAME;
    SSL_CTX *cctx = NULL, *sctx = NULL;
    int ret = 1, testresult = 0;
    char group[1024] = {0};
    char keypath_ca[300];
    char pubpath_ca[300];
    char keypath_c[300];
    char pubpath_c[300];
    char keypath[300];
    char pubpath[300];
    char *certsdir = "certs";
#ifndef OPENSSL_SYS_VMS
    const char *sep = "/";
#else
    const char *sep = "";
#endif
    sprintf(group, "sig: %s, kem: %s\n", sig_name, kem_name);
    
    fputs(group, stdout);

    sprintf(keypath_ca, "%s%s%s%s", certsdir, sep, sig_name, "_ca.key.pem");
    sprintf(pubpath_ca, "%s%s%s%s", certsdir, sep, sig_name, "_ca.pub.pem");
    sprintf(keypath_c, "%s%s%s%s", certsdir, sep, sig_name, "_cli.key.pem");
    sprintf(pubpath_c, "%s%s%s%s", certsdir, sep, sig_name, "_cli.pub.pem");
    sprintf(keypath, "%s%s%s%s", certsdir, sep, sig_name, ".key.pem");
    sprintf(pubpath, "%s%s%s%s", certsdir, sep, sig_name, ".pub.pem");
    /* ensure certsdir exists */
    if (mkdir(certsdir, 0700)) {
        if (errno != EEXIST) {
            fprintf(stderr, "Couldn't create certsdir %s: Err = %d\n", certsdir,
                    errno);
            ret = -1;
            goto err;
        }
    }
    if (!create_key(libctx, (char *)sig_name, keypath_ca, pubpath_ca, keypath_c, pubpath_c, keypath, pubpath)) {
        fprintf(stderr, "Cert/keygen failed for %s\n", sig_name);
        ret = -1;
        goto err;
    }
err:
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return ret;
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



static int cert_create(){
    char *sig_name = THIS_SIG_NAME;
    char *kem_name = THIS_KEM_NAME;
    SSL_CTX *cctx = NULL, *sctx = NULL;
    int ret = 1, testresult = 0;
    char group[1024] = {0};
    char certpath_ca[300];
    char key_ca[300];
    char pub_ca[300];
    char certpath_c[300];
    char pub_c[300];
    char certpath[300];
    char pub[300];
    char *certsdir = "certs";
#ifndef OPENSSL_SYS_VMS
    const char *sep = "/";
#else
    const char *sep = "";
#endif
    sprintf(group, "sig: %s, kem: %s\n", sig_name, kem_name);
    
    fputs(group, stdout);

    sprintf(certpath_ca, "%s%s%s%s", certsdir, sep, sig_name, "_ca.crt.pem");
    sprintf(key_ca, "%s%s%s%s", certsdir, sep, sig_name, "_ca.key.pem");
    sprintf(pub_ca, "%s%s%s%s", certsdir, sep, sig_name, "_ca.pub.pem");
    sprintf(certpath_c, "%s%s%s%s", certsdir, sep, sig_name, "_cli.crt.pem");
    sprintf(pub_c, "%s%s%s%s", certsdir, sep, sig_name, "_cli.pub.pem");
    sprintf(certpath, "%s%s%s%s", certsdir, sep, sig_name, ".crt.pem");
    sprintf(pub, "%s%s%s%s", certsdir, sep, sig_name, ".pub.pem");
    /* ensure certsdir exists */
    if (mkdir(certsdir, 0700)) {
        if (errno != EEXIST) {
            fprintf(stderr, "Couldn't create certsdir %s: Err = %d\n", certsdir,
                    errno);
            ret = -1;
            goto err;
        }
    }
    if (!create_cert(libctx, (char *)sig_name, certpath_ca, key_ca, pub_ca, certpath_c, pub_c, certpath, pub)) {
        fprintf(stderr, "cert failed for %s\n", sig_name);
        ret = -1;
        goto err;
    }
err:
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return ret;
}


static int cert_verify(){
    char *sig_name = THIS_SIG_NAME;
    char *kem_name = THIS_KEM_NAME;
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

    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests(); 

    sprintf(certpath_ca, "%s%s%s%s", certsdir, sep, sig_name, "_ca.crt.pem");
    sprintf(certpath_c, "%s%s%s%s", certsdir, sep, sig_name, "_cli.crt.pem");
    sprintf(privkeypath_c, "%s%s%s%s", certsdir, sep, sig_name, "_cli.key.pem");
    sprintf(certpath, "%s%s%s%s", certsdir, sep, sig_name, ".crt.pem");
    sprintf(privkeypath, "%s%s%s%s", certsdir, sep, sig_name, ".key.pem");

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

    sprintf(certpath_ca, "%s%s%s%s", certsdir, sep, sig_name, "_ca.crt.pem");
    sprintf(certpath_c, "%s%s%s%s", certsdir, sep, sig_name, "_cli.crt.pem");
    sprintf(privkeypath_c, "%s%s%s%s", certsdir, sep, sig_name, "_cli.key.pem");
    sprintf(certpath, "%s%s%s%s", certsdir, sep, sig_name, ".crt.pem");
    sprintf(privkeypath, "%s%s%s%s", certsdir, sep, sig_name, ".key.pem");

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



void print_help(){

    printf("keygen        : pq key generation \n");
    printf("oqs-kem       : pq key encap/decap using liboqs \n");
    printf("oqs-sig       : pq signature using liboqs \n");
    printf("cert-gen      : pq certificate generation \n");
    printf("cert-verify   : pq certificate verification \n");
    printf("tls           : pq tls \n");

}


#define nelem(a) (sizeof(a) / sizeof((a)[0]))

int main(int argc, char *argv[]) {
    size_t i;
    int errcnt = 0, test = 0, query_nocache;
    
    T((libctx = OSSL_LIB_CTX_new()) != NULL);
    messagelen = strlen(message);
    if(argc != 2){
        printf("invalid argument\n");
        print_help();
        return -1;
    }
    if(strcmp(argv[1], "keygen") == 0){
        if (key_create() == 1) {
            fprintf(stderr, cGREEN "  keygen test succeeded" cNORM "\n");
        } else {
            fprintf(stderr, cRED "  keygen test failed" cNORM "\n");
            ERR_print_errors_fp(stderr);
            errcnt++;
        }
    } else if(strcmp(argv[1], "oqs-kem") == 0){
        if (qs_kem() == OQS_SUCCESS) {
            fprintf(stderr, cGREEN "  KEM test succeeded" cNORM "\n");
        } else {
            fprintf(stderr, cRED "  KEM test failed" cNORM "\n");
            ERR_print_errors_fp(stderr);
            errcnt++;
        }
    } else if (strcmp(argv[1], "oqs-sig") == 0){        
        if ( qs_signatures() == OQS_SUCCESS) {
            fprintf(stderr, cGREEN "sig test succeeded" cNORM "\n");
        } else {
            errcnt += 1;
            fprintf(stderr, cRED "sig test failed" cNORM "\n");
        }
    } else if (strcmp(argv[1], "cert-gen") == 0){
        if(cert_create() == 1) {
            fprintf(stderr, cGREEN "cert create test succeeded" cNORM "\n");
        } else {
            errcnt += 1;
            fprintf(stderr, cRED "cert create test failed" cNORM "\n");
        }
    }else if (strcmp(argv[1], "cert-verify") == 0){
        if(cert_verify() == 1) {
            fprintf(stderr, cGREEN "cert verify test succeeded" cNORM "\n");
        } else {
            errcnt += 1;
            fprintf(stderr, cRED "cert verify test failed" cNORM "\n");
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
    } else {
        printf("invalid argument: %s\n", argv[1]);
        print_help();
        return -1;
    }
    //OSSL_LIB_CTX_free(encodingctx);
    OSSL_LIB_CTX_free(libctx);
    TEST_ASSERT(errcnt == 0);
    return !test;
}