// SPDX-License-Identifier: Apache-2.0 AND MIT

#include "qs_tls.h"
int create_cert_key(OSSL_LIB_CTX *libctx, char *algname, char *certfilename_ca, char *certfilename_c, char *privkeyfilename_c, char *certfilename, char *privkeyfilename) {

    EVP_PKEY_CTX *evpctx_ca = EVP_PKEY_CTX_new_from_name(libctx, algname, OQSPROV_PROPQ);  
    EVP_PKEY_CTX *evpctx_c = EVP_PKEY_CTX_new_from_name(libctx, algname, OQSPROV_PROPQ);  
    EVP_PKEY_CTX *evpctx = EVP_PKEY_CTX_new_from_name(libctx, algname, OQSPROV_PROPQ);
    EVP_PKEY *pkey_ca = NULL;
    EVP_PKEY *pkey_c = NULL;
    EVP_PKEY *pkey = NULL;
    X509 *x509_ca = X509_new();
    X509 *x509_c = X509_new();
    X509 *x509 = X509_new();
    X509_NAME *name_ca = NULL;
    X509_NAME *name_c = NULL;
    X509_NAME *name = NULL;
    BIO *keybio_ca = NULL, *certbio_ca = NULL;
    BIO *keybio_c = NULL, *certbio_c = NULL;
    BIO *keybio = NULL, *certbio = NULL;

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

    if (!evpctx_ca || !EVP_PKEY_keygen_init(evpctx_ca) ||
        !EVP_PKEY_generate(evpctx_ca, &pkey_ca) || !pkey_ca || !x509_ca ||
        !ASN1_INTEGER_set(X509_get_serialNumber(x509_ca), 1) ||
        !X509_gmtime_adj(X509_getm_notBefore(x509_ca), 0) ||
        !X509_gmtime_adj(X509_getm_notAfter(x509_ca), 31536000L) ||
        !X509_set_pubkey(x509_ca, pkey_ca) || !(name_ca = X509_get_subject_name(x509_ca)) ||
        !X509_NAME_add_entry_by_txt(name_ca, "C", MBSTRING_ASC,
                                    (unsigned char *)"CH", -1, -1, 0) ||
        !X509_NAME_add_entry_by_txt(name_ca, "O", MBSTRING_ASC,
                                    (unsigned char *)"test.org", -1, -1, 0) ||
        !X509_NAME_add_entry_by_txt(name_ca, "CN", MBSTRING_ASC,
                                    (unsigned char *)"localhost_ca", -1, -1, 0) ||
        !X509_set_issuer_name(x509_ca, name_ca) ||
        !X509_sign(x509_ca, pkey_ca, EVP_sha256()) ||
        !(certbio_ca = BIO_new_file(certfilename_ca, "wb")) ||
        !PEM_write_bio_X509(certbio_ca, x509_ca))
        ret = 0;

    if (!evpctx_c || !EVP_PKEY_keygen_init(evpctx_c) ||
        !EVP_PKEY_generate(evpctx_c, &pkey_c) || !pkey_c || !x509_c ||
        !ASN1_INTEGER_set(X509_get_serialNumber(x509_c), 1) ||
        !X509_gmtime_adj(X509_getm_notBefore(x509_c), 0) ||
        !X509_gmtime_adj(X509_getm_notAfter(x509_c), 31536000L) ||
        !X509_set_pubkey(x509_c, pkey_c) || !(name_c = X509_get_subject_name(x509_c)) ||
        !X509_NAME_add_entry_by_txt(name_c, "C", MBSTRING_ASC,
                                    (unsigned char *)"CH", -1, -1, 0) ||
        !X509_NAME_add_entry_by_txt(name_c, "O", MBSTRING_ASC,
                                    (unsigned char *)"test.org", -1, -1, 0) ||
        !X509_NAME_add_entry_by_txt(name_c, "CN", MBSTRING_ASC,
                                    (unsigned char *)"localhost_c", -1, -1, 0) ||
        !X509_set_issuer_name(x509_c, name_ca) ||
        !X509_sign(x509_c, pkey_ca, EVP_sha256()) ||
        !(keybio_c = BIO_new_file(privkeyfilename_c, "wb")) ||
        !PEM_write_bio_PrivateKey(keybio_c, pkey_c, NULL, NULL, 0, NULL, NULL) ||
        !(certbio_c = BIO_new_file(certfilename_c, "wb")) ||
        !PEM_write_bio_X509(certbio_c, x509_c))
        ret = 0;

    if (!evpctx || !EVP_PKEY_keygen_init(evpctx) ||
        !EVP_PKEY_generate(evpctx, &pkey) || !pkey || !x509 ||
        !ASN1_INTEGER_set(X509_get_serialNumber(x509), 1) ||
        !X509_gmtime_adj(X509_getm_notBefore(x509), 0) ||
        !X509_gmtime_adj(X509_getm_notAfter(x509), 31536000L) ||
        !X509_set_pubkey(x509, pkey) || !(name = X509_get_subject_name(x509)) ||
        !X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
                                    (unsigned char *)"CH", -1, -1, 0) ||
        !X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                                    (unsigned char *)"test.org", -1, -1, 0) ||
        !X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                    (unsigned char *)"localhost", -1, -1, 0) ||
        !X509_set_issuer_name(x509, name_ca) ||
        !X509_sign(x509, pkey_ca, EVP_sha256()) ||
        !(keybio = BIO_new_file(privkeyfilename, "wb")) ||
        !PEM_write_bio_PrivateKey(keybio, pkey, NULL, NULL, 0, NULL, NULL) ||
        !(certbio = BIO_new_file(certfilename, "wb")) ||
        !PEM_write_bio_X509(certbio, x509))
        ret = 0;


    EVP_PKEY_free(pkey_ca);
    X509_free(x509_ca);
    EVP_PKEY_CTX_free(evpctx_ca);
    BIO_free(keybio_ca);
    BIO_free(certbio_ca);
    EVP_PKEY_free(pkey_c);
    X509_free(x509_c);
    EVP_PKEY_CTX_free(evpctx_c);
    BIO_free(keybio_c);
    BIO_free(certbio_c);
    EVP_PKEY_free(pkey);
    X509_free(x509);
    EVP_PKEY_CTX_free(evpctx);
    BIO_free(keybio);
    BIO_free(certbio);
    return ret;
}



static void print_cn_name(const char* label, X509_NAME* const name)
{
    int idx = -1, success = 0;
    unsigned char *utf8 = NULL;
    
    do
    {
        if(!name) break; /* failed */
        
        idx = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
        if(!(idx > -1))  break; /* failed */
        
        X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, idx);
        if(!entry) break; /* failed */
        
        ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);
        if(!data) break; /* failed */
        
        int length = ASN1_STRING_to_UTF8(&utf8, data);
        if(!utf8 || !(length > 0))  break; /* failed */
        
        fprintf(stdout, "  %s: %s\n", label, utf8);
        success = 1;
        
    } while (0);
    
    if(utf8)
        OPENSSL_free(utf8);
    
    if(!success)
        fprintf(stdout, "  %s: <not available>\n", label);
}

static int verify_callback(int preverify, X509_STORE_CTX* x509_ctx)
{
    
    int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
    int err = X509_STORE_CTX_get_error(x509_ctx);
    
    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME* iname = cert ? X509_get_issuer_name(cert) : NULL;
    X509_NAME* sname = cert ? X509_get_subject_name(cert) : NULL;
    
    print_cn_name("Issuer (cn)", iname);
    

    print_cn_name("Subject (cn)", sname);

    fprintf(stdout, "verify_callback (depth=%d)(preverify=%d)\n", depth, preverify);
    
    if(preverify == 0)
    {


        if(err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY)
            fprintf(stdout, "  Error = X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY\n");
        else if(err == X509_V_ERR_CERT_UNTRUSTED)
            fprintf(stdout, "  Error = X509_V_ERR_CERT_UNTRUSTED\n");
        else if(err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN)
            fprintf(stdout, "  Error = X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN\n");
        else if(err == X509_V_ERR_CERT_NOT_YET_VALID)
            fprintf(stdout, "  Error = X509_V_ERR_CERT_NOT_YET_VALID\n");
        else if(err == X509_V_ERR_CERT_HAS_EXPIRED)
            fprintf(stdout, "  Error = X509_V_ERR_CERT_HAS_EXPIRED\n");
        else if(err == X509_V_OK)
            fprintf(stdout, "  Error = X509_V_OK\n");
        else
            fprintf(stdout, "  Error = %d\n", err);
    }

    printf("client skip verify\n");

    return 1;
    //return preverify;

}

int create_tls1_3_ctx_pair(OSSL_LIB_CTX *libctx, SSL_CTX **sctx, SSL_CTX **cctx,
                                char *certfile_ca, char *certfile_c, char *privkeyfile_c, char *certfile, char *privkeyfile, int dtls_flag) {


    printf("pair\n");

    SSL_CTX *serverctx = NULL, *clientctx = NULL;

    if (sctx == NULL || cctx == NULL)
        goto err;

    if (dtls_flag) {
        serverctx = SSL_CTX_new_ex(libctx, NULL, DTLS_server_method());
        clientctx = SSL_CTX_new_ex(libctx, NULL, DTLS_client_method());
    } else {

        serverctx = SSL_CTX_new_ex(libctx, NULL, TLS_server_method());
        clientctx = SSL_CTX_new_ex(libctx, NULL, TLS_client_method());
    }

    if (serverctx == NULL || clientctx == NULL)
        goto err;

    SSL_CTX_set_options(serverctx, SSL_OP_ALLOW_CLIENT_RENEGOTIATION);
    if (dtls_flag) {
#ifdef DTLS1_3_VERSION
        if (!SSL_CTX_set_min_proto_version(serverctx, DTLS1_3_VERSION) ||
            !SSL_CTX_set_max_proto_version(serverctx, DTLS1_3_VERSION) ||
            !SSL_CTX_set_min_proto_version(clientctx, DTLS1_3_VERSION) ||
            !SSL_CTX_set_max_proto_version(clientctx, DTLS1_3_VERSION))
#endif
            goto err;
    } else {
        if (!SSL_CTX_set_min_proto_version(serverctx, TLS1_3_VERSION) ||
            !SSL_CTX_set_max_proto_version(serverctx, TLS1_3_VERSION) ||
            !SSL_CTX_set_min_proto_version(clientctx, TLS1_3_VERSION) ||
            !SSL_CTX_set_max_proto_version(clientctx, TLS1_3_VERSION))
            goto err;
    }

    
    if (!SSL_CTX_load_verify_locations(clientctx, certfile_ca, NULL))
        goto err;


    SSL_CTX_set_verify(clientctx, SSL_VERIFY_PEER, verify_callback);

    SSL_CTX_set_verify_depth(clientctx, 5);

    printf("client load ca: %s\n", certfile_ca);


    if (!SSL_CTX_use_certificate_file(clientctx, certfile_c, SSL_FILETYPE_PEM))
        goto err;

    if (!SSL_CTX_use_PrivateKey_file(clientctx, privkeyfile_c, SSL_FILETYPE_PEM))
        goto err;

    if (!SSL_CTX_check_private_key(clientctx))
        goto err;


    
    printf("client file done: %s\n", certfile_c);

    if (!SSL_CTX_use_certificate_file(serverctx, certfile, SSL_FILETYPE_PEM))
        goto err;

    if (!SSL_CTX_use_PrivateKey_file(serverctx, privkeyfile, SSL_FILETYPE_PEM))
        goto err;

    if (!SSL_CTX_check_private_key(serverctx))
        goto err;

    printf("server file done: %s\n", certfile);

    *sctx = serverctx;
    *cctx = clientctx;
    return 1;

err:
    SSL_CTX_free(serverctx);
    SSL_CTX_free(clientctx);
    return 0;
}


/* Create an SSL connection, but does not read any post-handshake
 * NewSessionTicket messages.
 * We stop the connection attempt (and return a failure value) if either peer
 * has SSL_get_error() return the value in the |want| parameter. The connection
 * attempt could be restarted by a subsequent call to this function.
 */
int create_tls_client(SSL *clientssl) {

    int i;
    unsigned char buf;
    size_t readbytes;

    int s;
    struct sockaddr_in addr;

    int port = 8080;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");


    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    int option = 1;

    //setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

    int c = connect(s, (struct sockaddr*)&addr, sizeof(addr));

    if(c < 0){

        printf("client connect failed\n");
        return 0;
    }

    int ret = SSL_set_fd(clientssl, s);

    if(ret != 1){

        printf("client ssl set fd failed\n");
        return 0;
    }



    ret = SSL_connect(clientssl);

    if(ret != 1){

        printf("client ssl connect failed\n");
        return 0;
    }

    

    X509* cert = SSL_get_peer_certificate(clientssl);
    if(cert == NULL) { 
        printf("client failed to get peer cert\n");
        exit(EXIT_FAILURE);
    } else {
        X509_free(cert); 

    } 

    printf("client ssl connected\n");


    
    ret = SSL_get_verify_result(clientssl);
    
    /*
    if (ret != X509_V_OK){
        printf("client ssl verify failed\n");
        return 0;
    };

    printf("client ssl verified\n");

    */

    printf("client ssl skip verifification\n");
    

    uint8_t wbuff[32] = {0};

    strcpy(wbuff, "hello");

    ret = SSL_write(clientssl, wbuff, 32);

    if(ret <= 0){

        printf("client ssl write failed\n");

        return 0;
    }

    sleep(3);

    return 1;
}

void* create_tls_server(void* varg){

    int i;
    unsigned char buf;
    size_t readbytes;

    int s;
    struct sockaddr_in addr;
    socklen_t addrlen;

    int port = 8080;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    int option = 1;

    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(s, 1) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    SSL *serverssl = (SSL *)varg;

    addrlen = sizeof(addr);

    printf("server accept...\n");

    int c = accept(s, (struct sockaddr*)&addr, &addrlen);

    if(c < 0){

        printf("accept failed\n");

        exit(EXIT_FAILURE);
    }

    printf("server accepted\n");

    SSL_set_fd(serverssl, c);

    int ret = SSL_accept(serverssl);

    if(ret != 1){

        printf("SSL accept failed\n");

        exit(EXIT_FAILURE);
    }

    printf("server ssl accepted\n");


    uint8_t rbuff[32] = {0};

    ret = SSL_read(serverssl, rbuff, 32);

    if(ret <= 0){
        printf("server read failed\n");
        exit(EXIT_FAILURE);
    }

    if(strcmp(rbuff, "hello") == 0){

        printf("success: server hello\n");
    } else {
        printf("failed: server\n");
    }

}

/*
 * Create an SSL connection including any post handshake NewSessionTicket
 * messages.
 */
int create_tls_connection(SSL *serverssl, SSL *clientssl, int want) {



    pthread_t tid;

    pthread_create(&tid, NULL, create_tls_server, (void*)serverssl);

    printf("server thread created\n");

    sleep(1);

    if (!create_tls_client(clientssl))
        return 0;

    /*
     * We attempt to read some data on the client side which we expect to fail.
     * This will ensure we have received the NewSessionTicket in TLSv1.3 where
     * appropriate. We do this twice because there are 2 NewSessionTickets.
     */
    /*
    for (i = 0; i < 2; i++) {
        if (SSL_read_ex(clientssl, &buf, sizeof(buf), &readbytes) > 0) {
            if (readbytes != 0)
                return 0;
        } else if (SSL_get_error(clientssl, 0) != SSL_ERROR_WANT_READ) {
            return 0;
        }
    }

    */
    return 1;
}