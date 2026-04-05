
#include "qs_common.h"



OSSL_LIB_CTX *libctx = NULL;


char *message = "asdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdf";
int messagelen = 0;


char *sig_name = THIS_SIG_NAME;
char *kem_name = THIS_KEM_NAME;
char group[QS_DEFAULT_STRLEN] = {0};
char certpath_ca[QS_DEFAULT_STRLEN];
char keypath_ca[QS_DEFAULT_STRLEN];
char pubpath_ca[QS_DEFAULT_STRLEN];
char certpath_c[QS_DEFAULT_STRLEN];
char keypath_c[QS_DEFAULT_STRLEN];
char pubpath_c[QS_DEFAULT_STRLEN];
char certpath[QS_DEFAULT_STRLEN];
char keypath[QS_DEFAULT_STRLEN];
char pubpath[QS_DEFAULT_STRLEN];
char kem_keypath_ca[QS_DEFAULT_STRLEN];
char kem_pubpath_ca[QS_DEFAULT_STRLEN];
char kem_keypath_c[QS_DEFAULT_STRLEN];
char kem_pubpath_c[QS_DEFAULT_STRLEN];
char kem_keypath[QS_DEFAULT_STRLEN];
char kem_pubpath[QS_DEFAULT_STRLEN];
char *certsdir = "certs";
#ifndef OPENSSL_SYS_VMS
char *sep = "/";
#else
char *sep = "";
#endif




int create_key(OSSL_LIB_CTX *libctx, char *algname, char *privkeyfile_ca, char *pubkeyfile_ca, char *privkeyfile_c, char *pubkeyfile_c, char *privkeyfile, char *pubkeyfile) {

    EVP_PKEY_CTX *evpctx_ca = EVP_PKEY_CTX_new_from_name(libctx, algname, NULL);  
    EVP_PKEY_CTX *evpctx_c = EVP_PKEY_CTX_new_from_name(libctx, algname, NULL);  
    EVP_PKEY_CTX *evpctx = EVP_PKEY_CTX_new_from_name(libctx, algname, NULL);

    EVP_PKEY *pkey_ca = NULL;
    EVP_PKEY *pkey_c = NULL;
    EVP_PKEY *pkey = NULL;


    char* message_ca = NULL;
    unsigned char *sig_ca;
    size_t siglen_ca = 0;

    char* message_c = NULL;
    unsigned char *sig_c;
    size_t siglen_c = 0;

    char* message = NULL;
    unsigned char *sig;
    size_t siglen = 0;

    BIO *keybio_ca = NULL, *pubbio_ca = NULL;
    BIO *keybio_c = NULL, *pubbio_c = NULL;
    BIO *keybio = NULL, *pubbio = NULL;



    int ret = 1;

    if (!evpctx_ca || EVP_PKEY_keygen_init(evpctx_ca) != 1 ||
        EVP_PKEY_generate(evpctx_ca, &pkey_ca) != 1 || !pkey_ca ||
        !(keybio_ca = BIO_new_file(privkeyfile_ca, "wb")) ||
        !PEM_write_bio_PrivateKey(keybio_ca, pkey_ca, NULL, NULL, 0, NULL, NULL) ||
        !(pubbio_ca = BIO_new_file(pubkeyfile_ca, "wb")) ||
        !PEM_write_bio_PUBKEY(pubbio_ca, pkey_ca))
        {
            return 0;
        }


    if (!evpctx_c || EVP_PKEY_keygen_init(evpctx_c) != 1 ||
        EVP_PKEY_generate(evpctx_c, &pkey_c) != 1|| !pkey_c ||
        !(keybio_c = BIO_new_file(privkeyfile_c, "wb")) ||
        !PEM_write_bio_PrivateKey(keybio_c, pkey_c, NULL, NULL, 0, NULL, NULL) ||
        !(pubbio_c = BIO_new_file(pubkeyfile_c, "wb")) ||
        !PEM_write_bio_PUBKEY(pubbio_c, pkey_c))
        {
            return 0;
        }


    if (!evpctx || EVP_PKEY_keygen_init(evpctx) != 1 ||
        EVP_PKEY_generate(evpctx, &pkey) != 1|| !pkey ||
        !(keybio = BIO_new_file(privkeyfile, "wb")) ||
        !PEM_write_bio_PrivateKey(keybio, pkey, NULL, NULL, 0, NULL, NULL) ||
        !(pubbio = BIO_new_file(pubkeyfile, "wb")) ||
        !PEM_write_bio_PUBKEY(pubbio, pkey))
        {
            return 0;
        }

    EVP_PKEY_free(pkey_ca);
    EVP_PKEY_CTX_free(evpctx_ca);
    BIO_free(keybio_ca);
    BIO_free(pubbio_ca);
    EVP_PKEY_free(pkey_c);
    EVP_PKEY_CTX_free(evpctx_c);
    BIO_free(keybio_c);
    BIO_free(pubbio_c);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(evpctx);
    BIO_free(keybio);
    BIO_free(pubbio);
    return ret;
}

static int set_ext_ctx(X509V3_CTX* extctx, X509* cert){

    X509V3_set_ctx(extctx, cert, cert, NULL, NULL, 0);

    return 1;
}

int create_cert(OSSL_LIB_CTX *libctx, char *algname, char *certfilename_ca, char *key_ca, char *pub_ca, char *certfilename_c, char* pub_c, char *certfilename, char *pub) {

    FILE* fp = NULL;
    

    EVP_PKEY_CTX *evpctx_ca = NULL;  
    EVP_PKEY_CTX *evpctx_c = NULL;
    EVP_PKEY_CTX *evpctx = NULL;

    EVP_PKEY *pkey_ca = NULL;
    EVP_PKEY *pubkey_ca = NULL;
    EVP_PKEY *pkey_c = NULL;
    EVP_PKEY *pkey = NULL;

    X509V3_CTX extctx;
    X509_EXTENSION *extension_usage = NULL;

    X509V3_set_ctx_nodb(&extctx);


    EVP_MD_CTX *mdctx_ca = NULL;
    EVP_MD_CTX *mdctx_c = NULL;
    EVP_MD_CTX *mdctx = NULL;

    char* message_ca = NULL;
    unsigned char *sig_ca;
    size_t siglen_ca = 0;

    char* message_c = NULL;
    unsigned char *sig_c;
    size_t siglen_c = 0;

    char* message = NULL;
    unsigned char *sig;
    size_t siglen = 0;

    X509 *x509_ca = X509_new();
    X509 *x509_c = X509_new();
    X509 *x509 = X509_new();
    X509_NAME *name_ca = NULL;
    X509_NAME *name_c = NULL;
    X509_NAME *name = NULL;
    BIO *certbio_ca = NULL;
    BIO *certbio_c = NULL;
    BIO *certbio = NULL;

    fp = fopen(key_ca, "r");
    pkey_ca = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    fp = fopen(pub_ca, "r");
    /*
    if(!PEM_read_PUBKEY(fp, &pkey_ca, NULL, NULL)){
        printf("failed to read ca pub key\n");
        return 0;
    }
    */
    pubkey_ca = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);

    fp = fopen(pub_c, "r");
    pkey_c = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);

    fp = fopen(pub, "r");
    pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);

    evpctx_ca = EVP_PKEY_CTX_new(pkey_ca, NULL);
    evpctx_c = EVP_PKEY_CTX_new(pkey_c, NULL);
    evpctx = EVP_PKEY_CTX_new(pkey, NULL);


    /*
    X509_EXTENSION *ext_c = NULL;
    ASN1_OCTET_STRING *skid_c = NULL;
    AUTHORITY_KEYID *akid_c = NULL; 
    unsigned char md_c[EVP_MAX_MD_SIZE];
    unsigned int md_len_c = 0;

    X509_EXTENSION *ext = NULL;
    ASN1_OCTET_STRING *skid = NULL;
    AUTHORITY_KEYID *akid = NULL; 
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    */
    int ret = 1;

    if (!evpctx_ca || !pkey_ca || !x509_ca ||
        !X509_set_version(x509_ca, 2) ||
        !ASN1_INTEGER_set(X509_get_serialNumber(x509_ca), 1) ||
        !X509_gmtime_adj(X509_getm_notBefore(x509_ca), 0) ||
        !X509_gmtime_adj(X509_getm_notAfter(x509_ca), 31536000L) ||
        X509_set_pubkey(x509_ca, pubkey_ca) != 1 || !(name_ca = X509_get_subject_name(x509_ca)) ||
        !X509_NAME_add_entry_by_txt(name_ca, "C", MBSTRING_ASC,
                                    (unsigned char *)"CH", -1, -1, 0) ||
        !X509_NAME_add_entry_by_txt(name_ca, "O", MBSTRING_ASC,
                                    (unsigned char *)"test.org", -1, -1, 0) ||
        !X509_NAME_add_entry_by_txt(name_ca, "CN", MBSTRING_ASC,
                                    (unsigned char *)"localhost_ca", -1, -1, 0) ||
        !X509_set_issuer_name(x509_ca, name_ca) ||
        !set_ext_ctx(&extctx, x509_ca)||
        !(extension_usage = X509V3_EXT_conf_nid(NULL, &extctx, NID_basic_constraints, "critical,CA:TRUE")) ||
        !X509_add_ext(x509_ca, extension_usage, -1)||
//        !(mdctx_ca = EVP_MD_CTX_new()) ||
//        !EVP_DigestSignInit_ex(mdctx_ca, NULL, "SHAKE128", libctx, NULL, pkey_ca, NULL) ||
//        !X509_sign_ctx(x509_ca, mdctx_ca) ||
        X509_sign(x509_ca, pkey_ca, NULL) == 0 ||
        !(certbio_ca = BIO_new_file(certfilename_ca, "wb")) ||
        !PEM_write_bio_X509(certbio_ca, x509_ca))
        {
            printf("!ca\n");
            return 0;
        }

    if (!evpctx_c || !pkey_c || !x509_c ||
        !X509_set_version(x509_c, 2) ||
        !ASN1_INTEGER_set(X509_get_serialNumber(x509_c), 1) ||
        !X509_gmtime_adj(X509_getm_notBefore(x509_c), 0) ||
        !X509_gmtime_adj(X509_getm_notAfter(x509_c), 31536000L) ||
        X509_set_pubkey(x509_c, pkey_c) != 1 || !(name_c = X509_get_subject_name(x509_c)) ||
        !X509_NAME_add_entry_by_txt(name_c, "C", MBSTRING_ASC,
                                    (unsigned char *)"CH", -1, -1, 0) ||
        !X509_NAME_add_entry_by_txt(name_c, "O", MBSTRING_ASC,
                                    (unsigned char *)"test.org", -1, -1, 0) ||
        !X509_NAME_add_entry_by_txt(name_c, "CN", MBSTRING_ASC,
                                    (unsigned char *)"localhost_c", -1, -1, 0) ||
        !X509_set_issuer_name(x509_c, name_ca) ||
 //       !(mdctx_c = EVP_MD_CTX_new()) ||
 //       !EVP_DigestSignInit_ex(mdctx_c, NULL, "SHAKE128", libctx, NULL, pkey_ca, NULL) ||
 //       !X509_sign_ctx(x509_c, mdctx_c) ||
        X509_sign(x509_c, pkey_ca, NULL) == 0 ||
        !(certbio_c = BIO_new_file(certfilename_c, "wb")) ||
        !PEM_write_bio_X509(certbio_c, x509_c))
        {
            printf("!c\n");
            return 0;
        }

    if (!evpctx || !pkey || !x509 ||
        !X509_set_version(x509, 2) ||
        !ASN1_INTEGER_set(X509_get_serialNumber(x509), 1) ||
        !X509_gmtime_adj(X509_getm_notBefore(x509), 0) ||
        !X509_gmtime_adj(X509_getm_notAfter(x509), 31536000L) ||
        X509_set_pubkey(x509, pkey) != 1 || !(name = X509_get_subject_name(x509)) ||
        !X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
                                    (unsigned char *)"CH", -1, -1, 0) ||
        !X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                                    (unsigned char *)"test.org", -1, -1, 0) ||
        !X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                    (unsigned char *)"localhost", -1, -1, 0) ||
        !X509_set_issuer_name(x509, name_ca) ||
//        !(mdctx = EVP_MD_CTX_new()) ||
//        !EVP_DigestSignInit_ex(mdctx, NULL, "SHAKE128", libctx, NULL, pkey_ca, NULL) ||
//        !X509_sign_ctx(x509, mdctx) ||
        X509_sign(x509, pkey_ca, NULL) == 0 ||
        !(certbio = BIO_new_file(certfilename, "wb")) ||
        !PEM_write_bio_X509(certbio, x509))
        {
            printf("!\n");
            return 0;
        }


    EVP_PKEY_free(pkey_ca);
    X509_free(x509_ca);
    EVP_PKEY_CTX_free(evpctx_ca);
    BIO_free(certbio_ca);
    EVP_PKEY_free(pkey_c);
    X509_free(x509_c);
    EVP_PKEY_CTX_free(evpctx_c);
    BIO_free(certbio_c);
    EVP_PKEY_free(pkey);
    X509_free(x509);
    EVP_PKEY_CTX_free(evpctx);
    BIO_free(certbio);
    return ret;
}

int qs_init(){
    T((libctx = OSSL_LIB_CTX_new()) != NULL);
    messagelen = strlen(message);
    sprintf(group, "sig: %s, kem: %s\n", sig_name, kem_name);
    fputs(group, stdout);
    sprintf(certpath_ca, "%s%s%s%s", certsdir, sep, sig_name, "_ca.crt.pem");
    sprintf(keypath_ca, "%s%s%s%s", certsdir, sep, sig_name, "_ca.key.pem");
    sprintf(pubpath_ca, "%s%s%s%s", certsdir, sep, sig_name, "_ca.pub.pem");
    sprintf(certpath_c, "%s%s%s%s", certsdir, sep, sig_name, "_cli.crt.pem");
    sprintf(keypath_c, "%s%s%s%s", certsdir, sep, sig_name, "_cli.key.pem");
    sprintf(pubpath_c, "%s%s%s%s", certsdir, sep, sig_name, "_cli.pub.pem");
    sprintf(certpath, "%s%s%s%s", certsdir, sep, sig_name, ".crt.pem");
    sprintf(keypath, "%s%s%s%s", certsdir, sep, sig_name, ".key.pem");
    sprintf(pubpath, "%s%s%s%s", certsdir, sep, sig_name, ".pub.pem");
    sprintf(kem_keypath_ca, "%s%s%s%s", certsdir, sep, kem_name, "_ca.key.pem");
    sprintf(kem_pubpath_ca, "%s%s%s%s", certsdir, sep, kem_name, "_ca.pub.pem");
    sprintf(kem_keypath_c, "%s%s%s%s", certsdir, sep, kem_name, "_cli.key.pem");
    sprintf(kem_pubpath_c, "%s%s%s%s", certsdir, sep, kem_name, "_cli.pub.pem");
    sprintf(kem_keypath, "%s%s%s%s", certsdir, sep, kem_name, ".key.pem");
    sprintf(kem_pubpath, "%s%s%s%s", certsdir, sep, kem_name, ".pub.pem");
    /* ensure certsdir exists */
    if (mkdir(certsdir, 0700)) {
        if (errno != EEXIST) {
            fprintf(stderr, "Couldn't create certsdir %s: Err = %d\n", certsdir,
                    errno);
            return -1;
        }
    }
    return 0;
}

int qs_exit(){
    if(libctx != NULL){
        OSSL_LIB_CTX_free(libctx);
    }
}

unsigned char* char2hex(int arrlen, unsigned char* bytearray){

    unsigned char* hexarray;

    int hexlen = 2;

    int outstrlen = hexlen * arrlen + 1;

    hexarray = (char*)malloc(outstrlen * sizeof(char));

    memset(hexarray, 0, outstrlen * sizeof(char));

    unsigned char* ptr = hexarray;

    for(int i = 0 ; i < arrlen; i++){

        sprintf(ptr + 2 * i, "%02X", bytearray[i]);

        printf("%d: %c%c ", i, ptr[2 * i], ptr[2 * i + 1]);
    }

    printf("\n");

    return hexarray;
}




unsigned char* hex2char(unsigned char* hexarray){

    unsigned char* chararray;

    int hexlen = strlen(hexarray);

    int outstrlen = hexlen  / 2;

    chararray = (char*)malloc(outstrlen * sizeof(char));

    memset(chararray, 0, outstrlen * sizeof(char));

    unsigned int n = 0;

    for(int i = 0 ; i < outstrlen; i++){

        sscanf(hexarray + 2 * i, "%2x", &n);

        chararray[i] = n;

        printf("%d: %c%c ", i, hexarray[2 * i], hexarray[2 * i + 1]);

    }

    printf("\n");

    return chararray;
}

