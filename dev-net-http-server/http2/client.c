#include "h2.h"



static int make_socket_non_blocking (int sfd){
    int flags, s;
    flags = fcntl (sfd, F_GETFL, 0);
    if (flags == -1){
        return -1;
    }
    flags |= O_NONBLOCK;
    s = fcntl (sfd, F_SETFL, flags);
    if (s == -1){
        return -2;
    }
    return 0;
}

static int verify_callback(int preverify, X509_STORE_CTX* x509_ctx){
    
    int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
    int err = X509_STORE_CTX_get_error(x509_ctx);

    printf("verify_callback (depth=%d)(preverify=%d)\n", depth, preverify);

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

static int hdl_request(sess_info2* si){
    client_h2_submit_request(si);
    return client_h2_session_send(si);
}

static int hdl_resp(sess_info2* si){
    int result = -1;
    unsigned char buff[H2_MAX_CHUNK];
    int n = SSL_read(si->ssl, buff, 1);
    if(n < 1){
        printf("ssl read error: %d\n", n);
        n = 0;
        goto exit;
    }
    result = nghttp2_session_mem_recv2(si->session, buff, (size_t)n);
    if (result < 0) {
        printf("Fatal error: hdl response: %s\n", nghttp2_strerror((int)result));
        return result;
    }
    if (client_h2_session_send(si) != 0) {
        printf("session send failed\n");
        return -1;
    }
exit:
    return n;
}

int client_run(char *url, char *ca_cert, char *client_cert, char *client_key){
    struct sockaddr_in serveaddr;
    struct epoll_event eevent;
    struct epoll_event *eevents = NULL;
    int epfd = 0;
    int n, i;
    sess_info2 si;

    urlparse_url u;
    char *host = NULL;
    uint16_t port;
    int rv;
    struct addrinfo hints;
    struct addrinfo* rp;
    int val = 1;

    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    const SSL_METHOD *method;
    const unsigned char *alpn = NULL;
    unsigned int alpnlen = 0;

    /* Parse the |uri| and stores its components in |u| */
    rv = urlparse_parse_url(url, strlen(url), 0, &u);
    if (rv != 0) {
        printf("Could not parse URl %s\n", url);
        return -1;
    }
    host = strndup(&url[u.field_data[URLPARSE_HOST].off],
                    u.field_data[URLPARSE_HOST].len);

    if (!(u.field_set & (1 << URLPARSE_PORT))) {
        port = 443;
    } else {
        port = u.port;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_STREAM;
    rv = getaddrinfo(host, NULL, &hints, &rp);
    if(rv != 0){
        printf("failed to get addr info\n");
        return -11;
    }
    struct sockaddr_in* ipv4 = (struct sockaddr_in*)rp->ai_addr;


    int fd = socket(AF_INET, SOCK_STREAM, 0); 
    if (fd == -1) { 
        printf("socket creation failed\n");
        return -1;
    } else {
        printf("socket successfully created\n");
    }
    /*
    if( setsockopt(SOCKFD, SOL_SOCKET, SO_REUSEADDR, (char *)&OPT,  
            sizeof(OPT)) < 0 )   
    {   
        perror("setsockopt");   
        exit(EXIT_FAILURE);   
    } 

    */  
    
    memset(&serveaddr, 0, sizeof(serveaddr)); 
    serveaddr.sin_family = AF_INET; 
    serveaddr.sin_addr = ipv4->sin_addr; 
    serveaddr.sin_port = htons(port); 
    if ((connect(fd, (struct sockaddr*)&serveaddr, sizeof(serveaddr))) != 0) { 
        printf("socket bind failed\n");
        return -1;
    } 

    method = TLS_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        printf("unable to create SSL context\n");
        goto err;
    }

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (SSL_CTX_set1_groups_list(ctx, "P-256") != 1) {
        printf("failed to set curve\n");
        goto err;
    }
#else  
    EC_KEY *ecdh;
    ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ecdh) {
        printf("failed to set curve\n");
        goto err;
    }
    SSL_CTX_set_tmp_ecdh(ctx, ecdh);
    EC_KEY_free(ecdh);
#endif

    if (!SSL_CTX_load_verify_locations(ctx, ca_cert, NULL)){
        printf("ca cert failed\n");
        goto err;
    }

    if (SSL_CTX_use_certificate_file(ctx, client_cert, SSL_FILETYPE_PEM) <= 0) {
        printf("use cert failed\n");
        goto err;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, client_key, SSL_FILETYPE_PEM) <= 0 ) {
        printf("use privkey failed\n");
        goto err;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);
    SSL_CTX_set_verify_depth(ctx, 5);
    SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
    SSL_CTX_set_cipher_list(ctx, H2_PREFERRED_CIPHERS);
    SSL_CTX_set_alpn_protos(ctx, (const unsigned char *)"\x02h2", 3);

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);

    if(SSL_connect(ssl) != 1){
        printf("failed to connect ssl\n");
        goto err;
    }
    SSL_get0_alpn_selected(ssl, &alpn, &alpnlen);
    if (alpn == NULL || alpnlen != 2 || memcmp("h2", alpn, 2) != 0) {
        fprintf(stderr, "h2 is not negotiated\n");
        goto err;
    }
    si.ssl = ssl;

    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&val, sizeof(val));
    si.fd = fd;
    /*
    if(make_socket_non_blocking(si.fd) < 0){
        printf("non-blocking failed\n");
        goto err;
    }

    epfd = epoll_create1(0);
    if(epfd < 0){
        printf("epoll creation failed\n");
        goto err;
    }

    eevent.data.fd = fd;
    eevent.events = EPOLLIN | EPOLLET;

    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &eevent) < 0){
        printf("epoll add failed\n");
        goto err;
    }    
    eevents = calloc(H2_MAXCONN + 1, sizeof(eevent));
    */
    si.stream_data = client_h2_create_http2_stream_data(url, &u);
    client_h2_initialize_nghttp2_session(&si);
    client_h2_send_connection_header(&si);
    rv = hdl_resp(&si);
    printf("resp handled: %d\n", rv);
    if(rv < 0){
        goto err;
    }
    rv = hdl_request(&si);
    printf("send request: %d\n", rv);
    if(rv < 0){
        goto err;
    }
    n = 0;
    i = 0;
    while (1){
        rv = hdl_resp(&si);
        printf("resp handled: %d\n", rv);
        if(rv < 0){
            break;
        }

        /*
        n = epoll_wait(epfd, eevents, H2_MAXCONN + 1, -1);
        for (i = 0 ; i < n; i ++){
            if (
                (eevents[i].events & EPOLLERR) ||
                (eevents[i].events & EPOLLHUP) ||
                (!(eevents[i].events & EPOLLIN))
            ){

                printf("epoll wait error\n");
                close(eevents[i].data.fd);
                continue;

            } else if (fd == eevents[i].data.fd){
                rv = hdl_resp(&si);
                printf("resp handled: %d\n", rv);
                if(rv < 0){
                    break;
                }
            } else {
                printf("??\n");
            }
        }
            */
    } 
err:
    close(fd);
    close(epfd);
    if(host != NULL){
        free(host);
    }
    if(eevents != NULL){
        free(eevents);
    }
    if(ctx != NULL){
        SSL_CTX_free(ctx);
    }
    if(si.session != NULL){
        nghttp2_session_del(si.session);
    }
    if(si.stream_data != NULL){
        client_h2_delete_http2_stream_data(si.stream_data);
    }

    return 0;
}