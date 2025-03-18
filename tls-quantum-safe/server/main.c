#include "tls_qs.h"

OSSL_LIB_CTX *libctx = NULL;

OSSL_PROVIDER *oqsprov = NULL;

SSL_CTX *serverctx = NULL;
SSL *serverssl = NULL;
int done = 0;



static void sigint_handler(int signal) {
    printf("Interrupt.\n");

    done = 1;

    int fd = SSL_get_fd(serverssl);

    close(fd);

}


static int run_tls_server(){

    int s;
    struct sockaddr_in addr;
    socklen_t addrlen;

    int port = 8080;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);


    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        printf("unable to create socket\n");
        return -1;
    }

    int option = 1;

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {

        printf("failed to bind\n");

        return -1;

    }

    if (listen(s, 1) < 0) {
        
        printf("failed to listen\n");

        return -1;
    }


    addrlen = sizeof(addr);

    printf("server ready to accept...\n");

    int c = accept(s, (struct sockaddr*)&addr, &addrlen);

    if(c < 0){

        printf("accept failed\n");

        return -1;
    }

    printf("server accepted\n");

    SSL_set_fd(serverssl, c);

    int ret = SSL_accept(serverssl);

    if(ret != 1){

        printf("SSL accept failed\n");

        return -1;
    }

    printf("server ssl accepted\n");

    while(done == 0){

        uint8_t rbuff[RWBUFF_LEN] = {0};
        uint8_t wbuff[RWBUFF_LEN] = {0};

        int rval = 0;
        int n = 0;

        while(rval != RWBUFF_LEN){

            n = SSL_read(serverssl, rbuff + rval, RWBUFF_LEN - rval);
        
            if(n <= 0){
                printf("server read failed: %d\n", n);
                
                return -1;
            }
        
            rval += n;

        }

        if(n <= 0){
            continue;
        }

        printf("server got: %s\n", rbuff);

        strncpy(wbuff, rbuff, RWBUFF_LEN);

        n = SSL_write(serverssl, wbuff, RWBUFF_LEN);

        if(n <= 0){

            printf("write failed: %d\n", n);

            return -1;
        }

    }

    return 0;
}

static int run(){

    int result;

    serverctx = SSL_CTX_new_ex(libctx, NULL, TLS_server_method());

    if(serverctx == NULL){

        printf("failed to get new ssl ctx\n");

        result = -1;
        goto mainexit;
    }

    if(!SSL_CTX_set_min_proto_version(serverctx, TLS1_3_VERSION) ||
       !SSL_CTX_set_max_proto_version(serverctx, TLS1_3_VERSION)){

        printf("failed to set tlsv1.3 \n");

        result = -1;
        goto mainexit;
    } 

    SSL_CTX_set_options(serverctx, SSL_OP_ALLOW_CLIENT_RENEGOTIATION);

    if (!SSL_CTX_use_certificate_file(serverctx, SERVER_CERT, SSL_FILETYPE_PEM)){

        printf("failed to load server cert: ./%s\n", SERVER_CERT);

        result = -1;
        goto mainexit;
    }

    if (!SSL_CTX_use_PrivateKey_file(serverctx, SERVER_KEY, SSL_FILETYPE_PEM)){

        printf("failed to load server key: ./%s\n", SERVER_KEY);

        result = -1;
        goto mainexit;
    }

    if (!SSL_CTX_check_private_key(serverctx)){

        printf("failed to check private key\n");

        result = -1;
        goto mainexit;
    }


    serverssl = SSL_new(serverctx);

    if(serverssl == NULL){

        printf("failed to get new ssl\n");

        result = -1;

        goto mainexit;
    }

    if(!SSL_set1_groups_list(serverssl, THIS_KEM_ALGORITHM)){

        printf("failed to set kem algorithm: %s\n", THIS_KEM_ALGORITHM);

        result = -1;

        goto mainexit;

    }

    result = run_tls_server();

mainexit:

    if(serverctx != NULL)
        SSL_CTX_free(serverctx);

    if(serverssl != NULL)
        SSL_free(serverssl);

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