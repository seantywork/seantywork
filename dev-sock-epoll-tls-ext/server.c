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


typedef struct slot_el slot_el;

typedef struct slot_el {
    int using;
    void *data;
    slot_el *next;
}slot_el;

typedef struct slot{
    pthread_mutex_t lock;
    slot_el *data;
}slot;

static slot* gbucket = NULL;


static slot *slot_init(){
    int i;
    slot *bucket = malloc(sizeof(slot));
    bucket->data = NULL;
    pthread_mutex_init(&bucket->lock, NULL);
    for(i = 0; i < H2_MAXCONN; i++){
        slot_el *n = calloc(1, sizeof(slot_el));
        n->next = bucket->data;
        bucket->data = n;
    }
    return bucket;
}

static int slot_add(slot *bucket, void *new_data, int (*add)(void **el_data, void *new_data)){
    int result = -1;
    slot_el *el = NULL;
    pthread_mutex_lock(&bucket->lock);
    el = bucket->data;
    for(;;){
        if(el == NULL){
            break;
        }
        if(el->using){
            el = el->next;
            continue;
        }
        if((result = add(&el->data, new_data)) < 0){
            el = el->next;
            continue;
        }
        el->using = 1;
        break; 
    }
    pthread_mutex_unlock(&bucket->lock);
    return result;
}

static int slot_op(slot *bucket, void *data, int (*op)(void **el_data, void *data)){
    int result = -1;
    slot_el *el = NULL;
    pthread_mutex_lock(&bucket->lock);
    el = bucket->data;
    for(;;){
        if(el == NULL){
            break;
        }
        if(!el->using){
            el = el->next;
            continue;
        }
        if((result = op(&el->data, data)) < 0){
            el = el->next;
            continue;
        }
        break;
    }
    pthread_mutex_unlock(&bucket->lock);
    return result;
}

static int slot_del(slot *bucket, void *data, int (*del)(void **el_data, void *data)){
    int result = -1;
    slot_el *el = NULL;
    pthread_mutex_lock(&bucket->lock);
    el = bucket->data;
    for(;;){
        if(el == NULL){
            break;
        }
        if(!el->using){
            el = el->next;
            continue;
        }
        if((result = del(&el->data, data)) < 0){
            el = el->next;
            continue;
        }
        el->using = 0;
        break;
    }
    pthread_mutex_unlock(&bucket->lock);
    return result;
}

static void slot_free(slot *bucket, void clear(void **el_data)){
    slot_el *el = NULL;
    slot_el *tmp = NULL;
    pthread_mutex_lock(&bucket->lock);
    for(;;){
        el = bucket->data;
        if(el == NULL){
            break;
        }
        tmp = el->next;
        clear(&el->data);
        free(el);
        bucket->data = tmp;
        break;
    }
    pthread_mutex_unlock(&bucket->lock);
    free(bucket);
}



static int _add(void **el_data, void *new_data){
    sess_info **el_si = (sess_info **)el_data;
    sess_info *new_si = (sess_info *)new_data;
    if(*el_si == NULL){
        *el_si = calloc(1, sizeof(sess_info));
    } else if((*el_si)->fd != new_si->fd){
        return -2;
    } else {
        if((*el_si)->ssl){
            SSL_free((*el_si)->ssl);
        }
        if((*el_si)->session){
            nghttp2_session_del((*el_si)->session);
        }
    }
    memcpy(*el_si, new_si, sizeof(sess_info));
    new_si->self = *el_si;
    return 0;
}

static int _get(void **el_data, void *data){
    sess_info **el_si = (sess_info **)el_data;
    sess_info *si = (sess_info *)data;
    if(*el_si == NULL){
        return -1;
    } else if((*el_si)->fd != si->fd){
        return -2;
    } 
    memcpy(si, *el_si, sizeof(sess_info));
    return 0;
}

static int _del(void **el_data, void *data){
    sess_info **el_si = (sess_info **)el_data;
    sess_info *si = (sess_info *)data;
    if(*el_si == NULL){
        return -1;
    } else if((*el_si)->fd != si->fd){
        return -2;
    } 
    if((*el_si)->ssl){
        SSL_free((*el_si)->ssl);
    }
    if((*el_si)->session){
        nghttp2_session_del((*el_si)->session);
    }
    free(*el_si);
    *el_si = NULL;
    return 0;
}

static void _clear(void **el_data){
    sess_info **el_si = (sess_info **)el_data;
    if(*el_si == NULL){
        return;
    }
    if((*el_si)->ssl){
        SSL_free((*el_si)->ssl);
    }
    if((*el_si)->session){
        nghttp2_session_del((*el_si)->session);
    }
    free(*el_si);
    return;
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


static void hdl_conn(SSL_CTX *ctx, int epfd, int fd){
    SSL *ssl;
    const unsigned char *alpn = NULL;
    unsigned int alpnlen = 0;
    while(1){
        struct sockaddr in_addr;
        socklen_t in_len;
        int infd;
        int ssl_accept_ret;
        in_len = sizeof(in_addr);
        int val = 1;
        ssl = NULL;
        alpn = NULL;
        sess_info si;
        struct epoll_event eevent;
        memset(&si, 0, sizeof(sess_info));
        infd = accept(fd, &in_addr, &in_len);
        if(infd == -1){
            if(
                (errno == EAGAIN) ||
                (errno == EWOULDBLOCK)
            ){
                printf("no more incoming conns\n");
                break;
            } else{
                printf("error handling incoming sock connection\n");
                break;
            }
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, infd);
        if((ssl_accept_ret = SSL_accept(ssl)) < 1){
            int sslerr =  SSL_get_error(ssl, ssl_accept_ret);
            printf("error handling tls handshake\n");
            if (ssl_accept_ret <=0 && (sslerr == SSL_ERROR_WANT_READ)) {
                printf("Need to wait until socket is readable.");
            } else if (ssl_accept_ret <=0 && (sslerr == SSL_ERROR_WANT_WRITE)) {
                printf("Need to wait until socket is writable\n");
            } else {
                printf("Need to wait until socket is ready.\n");
            }
            goto err;
        } 
        
        SSL_get0_alpn_selected(ssl, &alpn, &alpnlen);
        if (alpn == NULL || alpnlen != 2 || memcmp("h2", alpn, 2) != 0) {
            fprintf(stderr, "h2 is not negotiated\n");
            goto err;
        }
        si.ssl = ssl;

        if(make_socket_non_blocking(infd) < 0){
            printf("failed to non block to fd\n");
            goto err;
        }
        setsockopt(infd, IPPROTO_TCP, TCP_NODELAY, (char *)&val, sizeof(val));
        si.fd = infd;
        int res = slot_add(gbucket, &si, _add);
        if(res != 0){
            printf("failed to add to bucket: %d\n", res);
            goto err;
        }
        eevent.data.fd = infd;
        eevent.events = EPOLLIN | EPOLLET;
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, infd, &eevent) < 0){
            printf("handle epoll add failed\n");
            slot_del(gbucket, &si, _del);
        } else {
            printf("handle epoll add success\n"); 
        }
        server_h2_initialize_nghttp2_session(si.self);
        if (server_h2_send_connection_header(si.self) != 0 || server_h2_send(si.self) != 0) {
            printf("server conn header send failed\n");
            slot_del(gbucket, &si, _del);
            goto err;
        }
        continue;
err:
        if(ssl != NULL){
            SSL_free(ssl);
        }
        if(si.session != NULL){
            nghttp2_session_del(si.session);
        }
    }

    return;
}

static void hdl_data(int fd){
    sess_info si;
    int result = -1;
    int err = 0;
    int n =0;
    unsigned char buff[H2_MAX_CHUNK];
    si.fd = fd;
    if((result = slot_op(gbucket, &si, _get)) != 0){
        printf("data slot op failed: %d\n", result);
        goto exit;
    }
    for(;;){
        n = SSL_read(si.ssl, buff, H2_MAX_CHUNK);
        if(n < 1){
            if(err == SSL_ERROR_WANT_READ){
                goto exit;
            }
            if(err == SSL_ERROR_WANT_WRITE){
                goto exit;
            }
            printf("fatal: read: %d\n", err);
            slot_del(gbucket, &si, _del);
            goto exit;
        }
        
        printf("read: %d\n",n);
        for(int i = 0; i < n; i++){
            printf("%c", buff[i]);
        }
        printf("\n");
        result = server_h2_recv(&si, buff, (size_t)n);
        if(result < 0){
            printf("session recv error: %d\n", result);
            slot_del(gbucket, &si, _del);
            goto exit;
        }

    }
exit:
    return;
}

int server_run(char *portstr, char *ca_cert, char *server_cert, char *server_key){
    struct sockaddr_in serveaddr;
    struct epoll_event eevent;
    struct epoll_event *eevents = NULL;
    int epfd = 0;
    int n, i;
    unsigned short port = 0;
    SSL_CTX *ctx = NULL;
    const SSL_METHOD *method;

    sscanf(portstr, "%hu", &port);

    gbucket = slot_init();

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
    serveaddr.sin_addr.s_addr = htonl(INADDR_ANY); 
    serveaddr.sin_port = htons(port); 
    if ((bind(fd, (struct sockaddr*)&serveaddr, sizeof(serveaddr))) != 0) { 
        printf("socket bind failed\n");
        return -1;
    } 
    if((listen(fd, H2_MAXCONN)) != 0) { 
        printf("listen failed\n");
        return -1;
    } 

    method = TLS_server_method();
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

    if (SSL_CTX_use_certificate_file(ctx, server_cert, SSL_FILETYPE_PEM) <= 0) {
        printf("use cert failed\n");
        goto err;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, server_key, SSL_FILETYPE_PEM) <= 0 ) {
        printf("use privkey failed\n");
        goto err;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);
    SSL_CTX_set_verify_depth(ctx, 5);
    SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
    SSL_CTX_set_cipher_list(ctx, H2_PREFERRED_CIPHERS);
    SSL_CTX_set_alpn_select_cb(ctx, server_h2_alpn_select_proto_cb, NULL);

    if(make_socket_non_blocking(fd) < 0){
        printf("non-blocking failed\n");
        return -1;
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
    n = 0;
    i = 0;
    while(1){
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
                hdl_conn(ctx, epfd, fd);
                printf("new conn handled\n");
            } else{
                hdl_data(eevents[i].data.fd);
                printf("data handled\n");
            }

        }
    }
err:
    close(fd);
    close(epfd);
    if(gbucket){
        slot_free(gbucket, _clear);
    }
    if(eevents != NULL){
        free(eevents);
    }
    if(ctx != NULL){
        SSL_CTX_free(ctx);
    }
    return 0;
}