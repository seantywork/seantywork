#include "tls_qs.h"

OSSL_LIB_CTX *libctx = NULL;

OSSL_PROVIDER *oqsprov = NULL;

SSL_CTX *clientctx = NULL;
SSL *clientssl = NULL;



int done = 0;

static void sigint_handler(int signal) {
    printf("Interrupt.\n");

    done = 1;

    int fd = SSL_get_fd(clientssl);

    close(fd);
}

static void print_cn_name(const char* label, X509_NAME* const name){

    int idx = -1, success = 0;
    unsigned char *utf8 = NULL;
    
    do{
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

static int verify_callback(int preverify, X509_STORE_CTX* x509_ctx){
    
    int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
    int err = X509_STORE_CTX_get_error(x509_ctx);
    
    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME* iname = cert ? X509_get_issuer_name(cert) : NULL;
    X509_NAME* sname = cert ? X509_get_subject_name(cert) : NULL;
    
    print_cn_name("Issuer (cn)", iname);

    print_cn_name("Subject (cn)", sname);

    fprintf(stdout, "verify_callback (depth=%d)(preverify=%d)\n", depth, preverify);
    
    if(preverify == 0){

        fprintf(stdout, "verify error: %d\n", err);
    }

    return preverify;

}



static int run_tls_client(){


    int s;
    struct sockaddr_in addr;

    int port = 8080;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");


    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        printf("unable to create socket\n");
        
        return -1;
    }


    int c = connect(s, (struct sockaddr*)&addr, sizeof(addr));

    if(c < 0){

        printf("client connect failed\n");
        return -1;
    }

    int ret = SSL_set_fd(clientssl, s);

    if(ret != 1){

        printf("client ssl set fd failed\n");
        return -1;
    }


    ret = SSL_connect(clientssl);

    if(ret != 1){

        printf("client ssl connect failed\n");
        return -1;
    }


    X509* cert = SSL_get_peer_certificate(clientssl);
    if(cert == NULL) { 
        printf("client failed to get peer cert\n");
        return -1;
    } else {
        X509_free(cert); 

    } 

    printf("client ssl connected\n");
    
    ret = SSL_get_verify_result(clientssl);
    
    if (ret != X509_V_OK){
        printf("client ssl verify failed\n");
        return 0;
    }

    printf("client ssl verified\n");


    while(done == 0){
        
        uint8_t wbuff[RWBUFF_LEN] = {0};
        uint8_t rbuff[RWBUFF_LEN] = {0};

        printf("$: ");

        fgets(wbuff, RWBUFF_LEN, stdin);

        for(int i = 0 ; i < RWBUFF_LEN; i++){

            if(wbuff[i] == '\n'){
                wbuff[i] = 0;
                break;
            }
        }
    
        ret = SSL_write(clientssl, wbuff, RWBUFF_LEN);
    
        if(ret <= 0){
    
            printf("client ssl write failed: %d\n", ret);
    
            return -1;
        }

        int rval = 0;
        int n = 0;

        while(rval != RWBUFF_LEN){

            n = SSL_read(clientssl, rbuff + rval, RWBUFF_LEN - rval);

            if(n <= 0){

                printf("client failed to read: %d\n", n);

                break;
            }

            rval += n;

        }

        if(n <= 0){

            continue;
        }

        printf("client echo: %s\n", rbuff);
        
    }

    return 0;

}

static int run(){

    int result;

    clientctx = SSL_CTX_new_ex(libctx, NULL, TLS_client_method());

    if(clientctx == NULL){

        printf("failed to get new ssl ctx\n");

        result = -1;
        goto mainexit;
    }

    if(!SSL_CTX_set_min_proto_version(clientctx, TLS1_3_VERSION) ||
       !SSL_CTX_set_max_proto_version(clientctx, TLS1_3_VERSION)){

        printf("failed to set tlsv1.3 \n");

        result = -1;
        goto mainexit;
    } 

    if (!SSL_CTX_load_verify_locations(clientctx, CA_CERT, NULL)){

        printf("failed to load ca cert: ./%s\n", CA_CERT);

        result = -1;

        goto mainexit;
    }

    SSL_CTX_set_verify(clientctx, SSL_VERIFY_PEER, verify_callback);

    SSL_CTX_set_verify_depth(clientctx, 5);

    clientssl = SSL_new(clientctx);

    if(clientssl == NULL){

        printf("failed to get new ssl\n");

        result = -1;

        goto mainexit;
    }

    if(!SSL_set1_groups_list(clientssl, THIS_KEM_ALGORITHM)){

        printf("failed to set kem algorithm: %s\n", THIS_KEM_ALGORITHM);

        result = -1;

        goto mainexit;

    }


    result = run_tls_client();

mainexit:

    if(clientctx != NULL)
        SSL_CTX_free(clientctx);

    if(clientssl != NULL)
        SSL_free(clientssl);

    return result;

}



int main(){

    int result = 0;

    int cnt = 0;

    signal(SIGINT, sigint_handler);


    libctx = OSSL_LIB_CTX_new();

    if(libctx == NULL){

        printf("failed to get lib ctx\n");

        return -1;
    }

    load_oqs_provider(libctx, THIS_PROVIDER, THIS_CONFFILE);


    oqsprov = OSSL_PROVIDER_load(libctx, THIS_PROVIDER);

    result = run();


mainexit:

    if(libctx != NULL)
        OSSL_LIB_CTX_free(libctx);


    return result;
}