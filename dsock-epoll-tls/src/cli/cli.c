#include "socialize/cli/cli.h"
#include "socialize/utils.h"

extern char* PREFERRED_CIPHERS = "HIGH:!aNULL:!kRSA:!SRP:!PSK:!CAMELLIA:!RC4:!MD5:!DSS";

SSL_CTX* ctx = NULL;
SSL *ssl = NULL;

uint8_t header[HUB_HEADER_BYTELEN] = {0};
uint8_t body_len[HUB_BODY_BYTELEN] = {0};
uint64_t body_len_new = 0;
uint8_t *body = NULL;



int run_cli(char* addr){

    long res = 1;
    int ret = 1;
    unsigned long ssl_err = 0;
    
    int fd = 0;
    SSL_METHOD *method = NULL;

    

    char hostname[MAX_ID_LEN] = {0};

    init_openssl_library();

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

    res = SSL_CTX_load_verify_locations(ctx, VERIFICATION_LOCATION, NULL);

    if (res != 1){

        printf("load verification cert\n");

        goto EXIT_CLI;
    }

    ssl = SSL_new(ctx);

    if(ssl == NULL){

        printf("ssl new failed\n");

        goto EXIT_CLI;
    }

    res = connect_to_engine(addr, 30);

    if (res < 0){

        printf("failed to connect: %d\n", res);

        goto EXIT_CLI;
    }

    fd = res;

    SSL_set_fd(ssl, fd);

    res = SSL_connect(ssl);

    if(res != 1){

        printf("failed to handshake: %d\n", res);

        res = -1;

        goto EXIT_CLI;
    }

    
    X509* cert = SSL_get_peer_certificate(ssl);
    
    if(cert == NULL){

        printf("failed to get peer cert\n");

        goto EXIT_CLI;
    }
    

    res = SSL_get_verify_result(ssl);
    
    if (res != X509_V_OK){

        printf("ssl peer verification failed\n");

        res = -1;

        goto EXIT_CLI;
    }

    res = auth();

    if (res < 0){

        printf("failed to do auth\n");

        goto EXIT_CLI;
    }

    res = join();

    if (res < 0){

        printf("failed to do join\n");

        goto EXIT_CLI;
    }

    res = socialize();

    if(res < 0){

        printf("failed to socialize\n");

        goto EXIT_CLI;
    }

EXIT_CLI:

    if(NULL != ctx){
        SSL_CTX_free(ctx);
    }

    if(ssl != NULL){

        SSL_free(ssl);
    }
    return res;
}



int connect_to_engine(char* addr, long timeout){

    char hostname[MAX_ID_LEN] = {0};

    int port = 0;

    char ipaddr[32] = {0};

    int result = get_host_port(hostname, &port, addr);

    if(result < 0){

        printf("failed to get host and port\n");

        return result;
    }

    int status, valread, client_fd;
    struct sockaddr_in serv_addr;

    struct addrinfo hints;
    struct addrinfo* rp;


    char buffer[1024] = { 0 };
    if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        
        printf("socket creation error\n");

        return -1;
    }
 

    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_STREAM;

    result = getaddrinfo(hostname, NULL, &hints, &rp);

    if(result != 0){

        printf("failed to get addr info\n");

        return -11;
    }

    struct sockaddr_in* ipv4 = (struct sockaddr_in*)rp->ai_addr;

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    serv_addr.sin_addr = ipv4->sin_addr;

    struct timeval u_timeout;      
    u_timeout.tv_sec = 5;
    u_timeout.tv_usec = 0;
    
    
    if (setsockopt (client_fd, SOL_SOCKET, SO_RCVTIMEO, &u_timeout, sizeof(u_timeout)) < 0){

        printf("set recv timeout\n");

        return -3;
    }
    

    if (setsockopt (client_fd, SOL_SOCKET, SO_SNDTIMEO, &u_timeout, sizeof(u_timeout)) < 0) {

        printf("set send timeout\n");
    
        return -4;
    }
    

    
    int rc = 0;
    
    int sockfd_flags_before;

    sockfd_flags_before = fcntl(client_fd, F_GETFL,0);
    
    if(sockfd_flags_before < 0) {
    
        printf("failed to getfl\n");

        return -5;
    
    }
    
    
    if(fcntl(client_fd, F_SETFL, sockfd_flags_before | O_NONBLOCK)<0){


        printf("failed to setfl\n");

        return -6;
    
    } 


    if (connect(client_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {

        if ((errno != EWOULDBLOCK) && (errno != EINPROGRESS)) {

            rc = -11;

        } else {
            
            struct timespec now;

            clock_gettime(CLOCK_MONOTONIC_RAW, &now);

            struct timespec deadline;

            do{

                clock_gettime(CLOCK_MONOTONIC_RAW, &deadline);

                int ms_until_deadline = ((deadline.tv_sec - now.tv_sec) * 1000 + (deadline.tv_nsec - now.tv_nsec) / 1000000);
 
                if(ms_until_deadline > timeout) { 
                    rc = -10; 
                    break; 
                }
                
                struct pollfd pfds[] = { { .fd = client_fd, .events = POLLOUT } };
                rc = poll(pfds, 1, ms_until_deadline);
                
                if(rc > 0) {
                    int error = 0; 
                    socklen_t len = sizeof(error);
                    int retval = getsockopt(client_fd, SOL_SOCKET, SO_ERROR, &error, &len);
                    if(retval == 0) {
                        errno = error;
                    }
                    if(error != 0) {
                        rc = -11;
                    }
                }

            } while(rc == -11 && errno == EINTR);


            if(rc == -10) {
                
                errno = ETIMEDOUT;
                
            }

        }

    } 

    if(fcntl(client_fd,F_SETFL,sockfd_flags_before ) < 0) {

        return -20;
    }

    return client_fd;
}


int auth(){

    char cert[MAX_PW_LEN] = {0};

    int result = 0;

    if(TEST_CASE == 1){

        result = read_file_to_buffer(cert, MAX_PW_LEN, SUB1_CERT);

    } else if(TEST_CASE == 2){

        result = read_file_to_buffer(cert, MAX_PW_LEN, SUB2_CERT);

    } else {

        result = read_file_to_buffer(cert, MAX_PW_LEN, CERT_LOC);

    }


    if (result < 0){

        printf("failed to get cert\n");

        return result;
    }

    uint64_t result64 = (uint64_t)result;

    strcpy(header, HUB_HEADER_AUTHSOCK);

    body_len_new = htonll(result64);

    memcpy(body_len, &body_len_new, HUB_BODY_BYTELEN);

    body = (uint8_t*)malloc(result * sizeof(uint8_t));

    memset(body, 0, result * sizeof(uint8_t));

    memcpy(body, cert, result * sizeof(uint8_t));

    result = SSL_write(ssl, header, HUB_HEADER_BYTELEN);

    if (result < 0){

        printf("write auth header failed\n");

        free(body);

        return result;
    }

    result = SSL_write(ssl, body_len, HUB_BODY_BYTELEN);

    if (result < 0){

        printf("write auth body len failed\n");

        free(body);

        return result;
    }

    result = SSL_write(ssl, body, result64 * sizeof(uint8_t));

    if (result < 0){

        printf("write auth body failed\n");

        free(body);

        return result;
    }


    free(body);

    int recvlen = 0;

    int n = 0;

    while(recvlen != HUB_HEADER_BYTELEN){

        n = SSL_read(ssl, header + recvlen, HUB_HEADER_BYTELEN - recvlen);

        if(n <= 0){

            printf("read header failed\n");

            return -1;
        }

        recvlen += n;

    }

    recvlen = 0;

    while(recvlen != HUB_BODY_BYTELEN){

        n = SSL_read(ssl, body_len + recvlen, HUB_BODY_BYTELEN - recvlen);

        if(n <= 0){

            printf("read body len failed\n");

            return -1;
        }

        recvlen += n;

    }

    memcpy(&body_len_new, body_len, HUB_BODY_BYTELEN);

    uint64_t body_len_n = ntohll(body_len_new);

    body = (uint8_t*)malloc(body_len_n * sizeof(uint8_t));

    recvlen = 0;

    while(recvlen != body_len_n){

        n = SSL_read(ssl, body + recvlen, body_len_n - (uint64_t)recvlen);

        if(n <= 0){

            printf("read body failed\n");

            free(body);

            return -1;
        }

        recvlen += n;

    }

    printf("auth: %s\n", body);

    free(body);

    return 0;

}

int join(){

    char action[16] = {0};
    char roomid[MAX_ID_LEN] = {0};

    printf("[ create | join ]:  ");

    fgets(action, 16, stdin);

    for(int i = 0 ; i < 16; i++){

        if(action[i] == '\n'){

            action[i] = 0;

            break;
        }
    }

    memset(header, 0, HUB_HEADER_BYTELEN);

    if(strncmp(action, "create", 16) == 0){

        strcpy(header, HUB_HEADER_REGSOCK_CREATE);

    } else if(strncmp(action, "join", 16) == 0){

        strcpy(header, HUB_HEADER_REGSOCK_JOIN);

    } else {

        printf("wrong action: %s\n", action);

        return -1;
    }

    printf("roomid?: ");

    fgets(roomid, MAX_ID_LEN, stdin);

    int idlen = 0;

    for(int i = 0 ; i < MAX_ID_LEN; i++){

        if(roomid[i] == '\n'){

            roomid[i] = 0;

            break;
        }

        idlen += 1;
    }

    uint64_t result64 = (uint64_t)idlen;

    body_len_new = htonll(result64);

    memcpy(body_len, &body_len_new, HUB_BODY_BYTELEN);

    body = (uint8_t*)malloc(result64 * sizeof(uint8_t));

    memset(body, 0, result64 * sizeof(uint8_t));

    memcpy(body, roomid, result64 * sizeof(uint8_t));



    int result = SSL_write(ssl, header, HUB_HEADER_BYTELEN);

    if (result < 0){

        printf("write join header failed\n");

        free(body);

        return result;
    }

    result = SSL_write(ssl, body_len, HUB_BODY_BYTELEN);

    if (result < 0){

        printf("write join body len failed\n");

        free(body);

        return result;
    }
 
    result = SSL_write(ssl, body, result64 * sizeof(uint8_t));

    if (result < 0){

        printf("write join body failed\n");

        free(body);

        return result;
    }

    free(body);

    int recvlen = 0;

    int n = 0;

    while(recvlen != HUB_HEADER_BYTELEN){

        n = SSL_read(ssl, header + recvlen, HUB_HEADER_BYTELEN - recvlen);

        if(n <= 0){

            printf("read header failed\n");

            return -1;
        }

        recvlen += n;

    }

    recvlen = 0;

    while(recvlen != HUB_BODY_BYTELEN){

        n = SSL_read(ssl, body_len + recvlen, HUB_BODY_BYTELEN - recvlen);

        if(n <= 0){

            printf("read body len failed\n");

            return -1;
        }

        recvlen += n;

    }

    memcpy(&body_len_new, body_len, HUB_BODY_BYTELEN);

    uint64_t body_len_n = ntohll(body_len_new);

    body = (uint8_t*)malloc(body_len_n * sizeof(uint8_t));

    recvlen = 0;

    while(recvlen != body_len_n){

        n = SSL_read(ssl, body + recvlen, body_len_n - (uint64_t)recvlen);

        if(n <= 0){

            printf("read body failed\n");

            free(body);

            return -1;
        }

        recvlen += n;

    }

    printf("join: %s\n", body);

    free(body);

    return 0;

}


int socialize(){

    // TODO:
    //  fix prompt at the bottom

    printf("start socializing!\n");

    pthread_t rt;
    
    int res = pthread_create(&rt, NULL, reader, NULL);

    if(res < 0){
        printf("reader creation failed\n");

        return -1;
    }
    
    for(;;){

        char msg[MAX_BUFF] = {0};

        int ccount = 0;

        fgets(msg, MAX_BUFF, stdin);

        if(cli_done == 1){
            return 0;
        }

        for(int i = 0; i < MAX_BUFF; i++){

            if(msg[i] == '\n'){

                msg[i] = 0;

                break;
            }

            ccount += 1;
        }

        uint64_t result64 = (uint64_t)ccount;

        body_len_new = htonll(result64);
    
        memcpy(body_len, &body_len_new, HUB_BODY_BYTELEN);
    
        body = (uint8_t*)malloc(result64 * sizeof(uint8_t));
    
        memset(body, 0, result64 * sizeof(uint8_t));
    
        memcpy(body, msg, result64 * sizeof(uint8_t));
    
        int result = SSL_write(ssl, header, HUB_HEADER_BYTELEN);
    
        if (result < 0){
    
            printf("write header failed\n");

            goto SOCIALIZE_CONTINUE;
        }
    
        result = SSL_write(ssl, body_len, HUB_BODY_BYTELEN);
    
        if (result < 0){
    
            printf("write body len failed\n");
    
            goto SOCIALIZE_CONTINUE;
        }
     
        result = SSL_write(ssl, body, result64 * sizeof(uint8_t));
    
        if (result < 0){
    
            printf("write body failed\n");
    
            goto SOCIALIZE_CONTINUE;
        }

SOCIALIZE_CONTINUE:
    
        free(body);


    }

    return 0;

}

void* reader(void* varg){

    uint8_t rheader[HUB_HEADER_BYTELEN] = {0};
    uint8_t rbodylen[HUB_BODY_BYTELEN] = {0};
    uint64_t rbodylen_new = 0;
    uint8_t *rbody = NULL;

    int recvlen = 0;

    int n = 0;

    for(;;){

        recvlen = 0;
        n = 0;

        while(recvlen != HUB_HEADER_BYTELEN){

            n = SSL_read(ssl, header + recvlen, HUB_HEADER_BYTELEN - recvlen);
    
            if(cli_done == 1){
                printf("read exit\n");
                return NULL;
            }

            if(n <= 0){
    
                goto SOCIALIZE_R_CONTINUE;
            }
    
            recvlen += n;
    
        }
    
        recvlen = 0;
    
        while(recvlen != HUB_BODY_BYTELEN){
    
            n = SSL_read(ssl, rbodylen + recvlen, HUB_BODY_BYTELEN - recvlen);
    
            if(n <= 0){
    
                printf("read body len failed\n");
    
                goto SOCIALIZE_R_CONTINUE;
            }
    
            recvlen += n;
    
        }
    
        memcpy(&rbodylen_new, rbodylen, HUB_BODY_BYTELEN);
    
        uint64_t body_len_n = ntohll(rbodylen_new);
    
        rbody = (uint8_t*)malloc(body_len_n * sizeof(uint8_t));
    
        recvlen = 0;
    
        while(recvlen != body_len_n){
    
            n = SSL_read(ssl, rbody + recvlen, body_len_n - (uint64_t)recvlen);
    
            if(n <= 0){
    
                printf("read body failed\n");
    
                goto SOCIALIZE_R_CONTINUE;
            }
    
            recvlen += n;
    
        }

        printf("%s\n", rbody);

SOCIALIZE_R_CONTINUE:

        if(rbody != NULL){

            free(rbody);

            rbody = NULL;
        }

    }



}



void init_openssl_library(void)
{

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

void print_san_name(const char* label, X509* const cert)
{
    int success = 0;
    GENERAL_NAMES* names = NULL;
    unsigned char* utf8 = NULL;
    
    do
    {
        if(!cert) break; /* failed */
        
        names = X509_get_ext_d2i(cert, NID_subject_alt_name, 0, 0 );
        if(!names) break;
        
        int i = 0, count = sk_GENERAL_NAME_num(names);
        if(!count) break; /* failed */
        
        for( i = 0; i < count; ++i )
        {
            GENERAL_NAME* entry = sk_GENERAL_NAME_value(names, i);
            if(!entry) continue;
            
            if(GEN_DNS == entry->type)
            {
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
            else
            {
                fprintf(stderr, "  Unknown GENERAL_NAME type: %d\n", entry->type);
            }
        }

    } while (0);
    
    if(names)
        GENERAL_NAMES_free(names);
    
    if(utf8)
        OPENSSL_free(utf8);
    
    if(!success)
        fprintf(stdout, "  %s: <not available>\n", label);
    
}

int verify_callback(int preverify, X509_STORE_CTX* x509_ctx)
{
    
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


    return preverify;
}

void print_error_string(unsigned long err, const char* const label)
{
    const char* const str = ERR_reason_error_string(err);
    if(str)
        fprintf(stderr, "%s\n", str);
    else
        fprintf(stderr, "%s failed: %lu (0x%lx)\n", label, err, err);
}