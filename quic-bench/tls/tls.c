#include "tls.h"

char* PREFERRED_CIPHERS = "HIGH:!aNULL:!kRSA:!SRP:!PSK:!CAMELLIA:!RC4:!MD5:!DSS";

void init_openssl_library(void){

    (void)SSL_library_init();    
    SSL_load_error_strings();
    CONF_modules_load(NULL, NULL, CONF_MFLAGS_IGNORE_MISSING_FILE);
#if defined (OPENSSL_THREADS)
    /* https://www.openssl.org/docs/crypto/threads.html */
    fprintf(stdout, "Warning: thread locking is not implemented\n");
#endif
}

void print_cn_name(const char* label, X509_NAME* const name)
{
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
    
    if(utf8){
        OPENSSL_free(utf8);
    }
    if(!success){
        fprintf(stdout, "  %s: <not available>\n", label);
    }
}

void print_san_name(const char* label, X509* const cert){
    int success = 0;
    GENERAL_NAMES* names = NULL;
    unsigned char* utf8 = NULL;
    do{
        if(!cert) break; /* failed */  
        names = X509_get_ext_d2i(cert, NID_subject_alt_name, 0, 0 );
        if(!names) break;
        int i = 0, count = sk_GENERAL_NAME_num(names);
        if(!count) break; /* failed */
        for( i = 0; i < count; ++i ){
            GENERAL_NAME* entry = sk_GENERAL_NAME_value(names, i);
            if(!entry) continue;
            if(GEN_DNS == entry->type){
                int len1 = 0, len2 = -1;
                len1 = ASN1_STRING_to_UTF8(&utf8, entry->d.dNSName);
                if(utf8) {
                    len2 = (int)strlen((const char*)utf8);
                }
                if(len1 != len2) {
                    fprintf(stderr, "  Strlen and ASN1_STRING size do not match (embedded null?): %d vs %d\n", len2, len1);
                }
                if(utf8 && len1 && len2 && (len1 == len2)) {
                    fprintf(stdout, "  %s: %s\n", label, utf8);
                    success = 1;
                }
                if(utf8) {
                    OPENSSL_free(utf8), utf8 = NULL;
                }
            }
            else{
                fprintf(stderr, "  Unknown GENERAL_NAME type: %d\n", entry->type);
            }
        }
    } while (0);
    
    if(names){
        GENERAL_NAMES_free(names);
    }
    if(utf8){
        OPENSSL_free(utf8);
    }
    if(!success){
        fprintf(stdout, "  %s: <not available>\n", label);
    }
}

int verify_callback(int preverify, X509_STORE_CTX* x509_ctx){
    
    int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
    int err = X509_STORE_CTX_get_error(x509_ctx);
    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME* iname = cert ? X509_get_issuer_name(cert) : NULL;
    X509_NAME* sname = cert ? X509_get_subject_name(cert) : NULL;
    fprintf(stdout, "verify_callback (depth=%d)(preverify=%d)\n", depth, preverify);
    print_cn_name("Issuer (cn)", iname);
    print_cn_name("Subject (cn)", sname);
    if(depth == 0) {
        print_san_name("Subject (san)", cert);
    }
    if(preverify == 0){
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
    return preverify;
}


static int client(){

    SSL_CTX* ctx = NULL;
    SSL *ssl = NULL;
    SSL_METHOD *method = NULL;

    int result = 0;
    int sockfd = -1;

    struct addrinfo hints;
    struct addrinfo* rp;

    struct sockaddr_in servaddr;
    in_addr_t s_addr = inet_addr(SERVER_ADDR);
    int addr_port = SERVER_PORT;
    int keepalive = 1;
    int chunk = 0;
    int content_len = 0;
    int message_len = 0;
    float percent = 0;
    struct timeval t1, t2;

    uint64_t total_sent = 0;
    uint8_t data[INPUT_BUFF_CHUNK] = {0};


    method = SSLv23_method();
    if(method == NULL){
        printf("ssl null method\n");
        return -1;
    }
    ctx = SSL_CTX_new(method);
    if(ctx == NULL){
        printf("ctx null\n");
        return -2;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
    SSL_CTX_set_verify_depth(ctx, 5);    

    const long flags = SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
    
    SSL_CTX_set_options(ctx, flags);
    result = SSL_CTX_load_verify_locations(ctx, CERT_CA, NULL);

    if (result != 1){
        printf("load verification cert\n");
        return -3;
    }

    ssl = SSL_new(ctx);

    if(ssl == NULL){
        printf("ssl new failed\n");
        return -4;
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        fprintf(stderr, "socket creation failed\n");
        return -1;
    }
 
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_STREAM;
    result = getaddrinfo(SERVER_ADDR, NULL, &hints, &rp);
    if(result != 0){
        printf("failed to get addr info\n");
        return -11;
    }
    struct sockaddr_in* ipv4 = (struct sockaddr_in*)rp->ai_addr;

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr = ipv4->sin_addr;
    servaddr.sin_port = htons(addr_port);

    if (connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr))!= 0) {
        fprintf(stderr, "connection failed\n");
        return -2;
    }

    SSL_set_fd(ssl, sockfd);

    result = SSL_connect(ssl);
    if(result != 1){
        printf("failed to handshake: %d\n", result);
        return -3;
    }
    
    X509* cert = SSL_get_peer_certificate(ssl);
    if(cert == NULL){
        printf("failed to get peer cert\n");
        return -4;
    }
    
    result = SSL_get_verify_result(ssl);
    if (result != X509_V_OK){
        printf("ssl peer verification failed\n");
        return -5;
    }

    printf("connected, sending...\n");

    gettimeofday(&t1, NULL);

    while(keepalive){

        if(getrandom(data, INPUT_BUFF_CHUNK, 0) < 0){
            printf("getrandom failed\n");
            return -3;
        }

        int wb = SSL_write(ssl, data, INPUT_BUFF_CHUNK);

        if(wb <= 0){       
            keepalive = 0;
            continue;
        }

        total_sent += (uint64_t)wb;

        percent = ((float)total_sent / (float)INPUT_BUFF_MAX) * 100;

        //printf("progress: %.2f\n", percent);

        if(total_sent > INPUT_BUFF_MAX){
            keepalive = 0;
            continue;
        }

    }

    if(total_sent <= INPUT_BUFF_MAX){
        printf("connection closed before sending completed\n");
        return -4;
    }

    gettimeofday(&t2, NULL);

    uint32_t seconds = t2.tv_sec - t1.tv_sec;      
    uint32_t ms = (t2.tv_usec - t1.tv_usec) / 1000;
    
    printf("sec: %lu ms: %lu\n", seconds, ms);
    printf("total sent: " "%" PRIu64 "\n", total_sent);

    return 0;
}



static int server(){
    
    SSL *ssl;
    SSL_CTX *ctx;
    SSL_METHOD *method;
    
    int sockfd, connfd = -1; 
    struct sockaddr_in servaddr, cli; 
    int keepalive = 1;


    in_addr_t s_addr = INADDR_ANY;

    int addr_port = SERVER_PORT;
    int enable = 1;
    int clilen = sizeof(cli); 

    uint8_t data[INPUT_BUFF_CHUNK] = {0};

    
    SSL_library_init();


    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        printf("unable to create SSL context");
        return -1;
    }

    if (SSL_CTX_use_certificate_file(ctx, CERT_SERVER, SSL_FILETYPE_PEM) <= 0) {
        printf("failed to use server cert\n");
        return -2;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_SERVER, SSL_FILETYPE_PEM) <= 0 ) {
        printf("failed to use server key\n");
        return -3;
    }

    ssl = SSL_new(ctx);

    sockfd = socket(AF_INET, SOCK_STREAM, 0); 
    if (sockfd == -1) { 
        printf("socket creation failed...\n"); 
        return -1;
    } 
    servaddr.sin_family = AF_INET; 
    servaddr.sin_addr.s_addr = s_addr; 
    servaddr.sin_port = htons(addr_port); 
   
    if ((bind(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr))) != 0) { 
        fprintf(stderr, "socket bind failed\n"); 
        return -2;
    } 
   
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0){
        fprintf(stderr, "socket opt failed\n"); 
        return -3;
    }

    if ((listen(sockfd, 1)) != 0) { 
        fprintf(stderr,"socket listen failed\n"); 
        return -4;
    } 
    
    while(keepalive){

        connfd = accept(sockfd, (struct sockaddr*)&cli, (socklen_t*)&clilen); 
        if (connfd < 0) { 
            fprintf(stderr, "server accept failed\n"); 
            continue;
        }

        SSL_set_fd(ssl, connfd);

        if(SSL_accept(ssl) != 1){
            fprintf(stderr, "server ssl accept failed\n"); 
            continue;
        };

        printf("client connected\n");
        printf("receiving...\n");

        while(keepalive){

            int valread = 0;

            while(valread < INPUT_BUFF_CHUNK){

                int rb = SSL_read(ssl, data + valread, INPUT_BUFF_CHUNK - valread);
                if (rb <= 0){
                    keepalive = 0;
                    break;
                } 
                valread += rb;

            }

            if(keepalive == 0){
                continue;
            }
        }

        close(connfd);

    }
    return 0;
}



static void help(){

    printf("option: [c|s]\n");
    printf("c: client mode\n");
    printf("s: server mode\n");
}


int main(int argc, char** argv){

    int result = 0;

    if(argc != 2){

        help();

        return -1;
    }

    if(strcmp(argv[1], "c") == 0){

        result = client();

    } else if(strcmp(argv[1], "s") == 0){

        result = server();

    } else {

        help();

        return -1;
    }

    return result;
}