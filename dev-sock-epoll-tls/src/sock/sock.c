#include   "socialize/ctl.h"
#include   "socialize/sock/sock.h"
#include   "socialize/utils.h"

int SOCK_FD;
int SOCK_SERVLEN;
int SOCK_EPLFD;
struct epoll_event SOCK_EVENT;
struct epoll_event *SOCK_EVENTARRAY;

char CA_CERT[MAX_PW_LEN] = {0};

char CA_PRIV[MAX_PW_LEN] = {0};

char CA_PUB[MAX_PW_LEN] = {0};


struct CHANNEL_CONTEXT CHAN_CTX[MAX_CONN];

// struct SOCK_CONTEXT SOCK_CTX[MAX_CONN];

struct SOCK_CTL SOCK_CTL;

int init_all(){


    for(int i = 0 ; i < MAX_CONN;i ++){

        CHAN_CTX[i].ssl = NULL;
        CHAN_CTX[i].ctx = NULL;


    }

    SOCK_CTL.in_use = 1;

    pthread_mutex_init(&SOCK_CTL.slock, NULL);

    SOCK_CTL.size = MAX_CONN;

    SOCK_CTL.SOCK_CTX = (struct SOCK_CONTEXT**)malloc(MAX_CONN * sizeof(struct SOCK_CONTEXT*));

    SOCK_CTL.SOCK_CTX_LOCK = (struct SOCK_CONTEXT_LOCK**)malloc(MAX_CONN * sizeof(struct SOCK_CONTEXT_LOCK*));

    for(int i = 0; i < MAX_CONN; i++){

        SOCK_CTL.SOCK_CTX[i] = (struct SOCK_CONTEXT*)malloc(sizeof(struct SOCK_CONTEXT));

        SOCK_CTL.SOCK_CTX_LOCK[i] = (struct SOCK_CONTEXT_LOCK*)malloc(sizeof(struct SOCK_CONTEXT_LOCK));

        memset(SOCK_CTL.SOCK_CTX[i], 0, sizeof(struct SOCK_CONTEXT));

        pthread_mutex_init(&SOCK_CTL.SOCK_CTX_LOCK[i]->lock, NULL);

    }

    return 0;
}

int free_all(){

    pthread_mutex_lock(&SOCK_CTL.slock);

    SOCK_CTL.in_use = 0;

    for(int i = 0; i < SOCK_CTL.size; i++){

        free(SOCK_CTL.SOCK_CTX[i]);

        free(SOCK_CTL.SOCK_CTX_LOCK[i]);

    }

    free(SOCK_CTL.SOCK_CTX);

    free(SOCK_CTL.SOCK_CTX_LOCK);

    pthread_mutex_unlock(&SOCK_CTL.slock);
}

void sock_listen_and_serve(void* varg){

    int result = 0;

    SSL_library_init();

    result = read_file_to_buffer(CA_CERT, MAX_PW_LEN, HUB_CA_CERT);

    if(result < 0){

        fmt_logln(LOGFP, "failed to read ca cert");

        return;

    }

    result = read_file_to_buffer(CA_PRIV, MAX_PW_LEN, HUB_CA_PRIV);

    if(result < 0){

        fmt_logln(LOGFP, "failed to read ca priv");

        return;

    }


    result = read_file_to_buffer(CA_PUB, MAX_PW_LEN, HUB_CA_PUB);

    if(result < 0){

        fmt_logln(LOGFP, "failed to read ca pub");

        return;

    }



    struct sockaddr_in SERVADDR;


    //signal(SIGPIPE, SIG_IGN);

    SOCK_FD = socket(AF_INET, SOCK_STREAM, 0); 

    if (SOCK_FD == -1) { 

        fmt_logln(LOGFP, "socket creation failed");

        exit(EXIT_FAILURE); 
    } 
    else {

        fmt_logln(LOGFP, "socket successfully created");
    }
    /*
    if( setsockopt(SOCKFD, SOL_SOCKET, SO_REUSEADDR, (char *)&OPT,  
          sizeof(OPT)) < 0 )   
    {   
        perror("setsockopt");   
        exit(EXIT_FAILURE);   
    } 

    */  
     

    bzero(&SERVADDR, sizeof(SERVADDR)); 
   
    SERVADDR.sin_family = AF_INET; 
    SERVADDR.sin_addr.s_addr = htonl(INADDR_ANY); 
    SERVADDR.sin_port = htons(PORT_SOCK); 
   
    if ((bind(SOCK_FD, (struct sockaddr*)&SERVADDR, sizeof(SERVADDR))) != 0) { 
        

        fmt_logln(LOGFP, "socket bind failed");

        exit(EXIT_FAILURE); 
    } 
    
    if(make_socket_non_blocking(SOCK_FD) < 0){

        fmt_logln(LOGFP, "non-blocking failed");

        exit(EXIT_FAILURE);
    }
    

    if ((listen(SOCK_FD, MAX_CONN)) != 0) { 

        fmt_logln(LOGFP, "listen failed");

        exit(EXIT_FAILURE); 
    } 
    else{
        SOCK_SERVLEN = sizeof(SERVADDR); 
    }


    SOCK_EPLFD = epoll_create1(0);

    if(SOCK_EPLFD == -1){

        fmt_logln(LOGFP, "epoll creation failed");

        exit(EXIT_FAILURE);
    }

    SOCK_EVENT.data.fd = SOCK_FD;
    SOCK_EVENT.events = EPOLLIN | EPOLLET;
    
    if (epoll_ctl(SOCK_EPLFD, EPOLL_CTL_ADD, SOCK_FD, &SOCK_EVENT) < 0){

        fmt_logln(LOGFP,"epoll add failed");

        exit(EXIT_FAILURE);
    }    

    SOCK_EVENTARRAY = calloc(MAX_CONN, sizeof(SOCK_EVENT));


    while(TRUE){

        int n, i ;

        n = epoll_wait(SOCK_EPLFD, SOCK_EVENTARRAY, MAX_CONN, -1);

        for (i = 0 ; i < n; i ++){

            if (
                (SOCK_EVENTARRAY[i].events & EPOLLERR) ||
                (SOCK_EVENTARRAY[i].events & EPOLLHUP) ||
                (!(SOCK_EVENTARRAY[i].events & EPOLLIN))
            ){

                fmt_logln(LOGFP, "epoll wait error");

                close(SOCK_EVENTARRAY[i].data.fd);
                
                continue;

            } else if (SOCK_FD == SOCK_EVENTARRAY[i].data.fd){

                sock_handle_conn();

                fmt_logln(LOGFP, "new sock conn successfully handled");

            } else{

                sock_handle_client(SOCK_EVENTARRAY[i].data.fd);

                fmt_logln(LOGFP, "socket data successfully handled");


            }

        }


    }


    free(SOCK_EVENTARRAY);

    close(SOCK_FD);

    close(SOCK_EPLFD);


}





void sock_handle_conn(){


    while(TRUE){

        struct sockaddr in_addr;
        socklen_t in_len;
        int infd;
        SSL *ssl;
        SSL_CTX *ctx;

        int ssl_accept_ret;

        in_len = sizeof(in_addr);
   
        infd = accept(SOCK_FD, &in_addr, &in_len);

        if(infd == -1){

            if(
                (errno == EAGAIN) ||
                (errno == EWOULDBLOCK)
            ){

                fmt_logln(LOGFP, "all incoming sock connections handled");

                break;

            } else{
 
                fmt_logln(LOGFP, "error handling incoming sock connection");

                break;
            }
        }

        ctx = create_context();

        configure_context(ctx);

        ssl = SSL_new(ctx);

        SSL_set_fd(ssl, infd);
    
        if((ssl_accept_ret = SSL_accept(ssl)) < 1){

            int sslerr =  SSL_get_error(ssl, 0);

            fmt_logln(LOGFP, "error handling tls handshake");

            if (ssl_accept_ret <=0 && (sslerr == SSL_ERROR_WANT_READ)) {

                perror ("Need to wait until socket is readable.");

                fmt_logln(LOGFP, "ssl: %s", "Need to wait until socket is readable");

            } else if (ssl_accept_ret <=0 && (sslerr == SSL_ERROR_WANT_WRITE)) {

                perror ("Need to wait until socket is writable.");

                fmt_logln(LOGFP, "ssl: %s", "Need to wait until socket is writable");


            } else {
                perror ("Need to wait until socket is ready.");

                fmt_logln(LOGFP, "ssl: %s", "Need to wait until socket is ready");

            }

            shutdown (infd, 2);
            SSL_free (ssl);
            SSL_CTX_free(ctx);

            continue;

        } 


        if(make_socket_non_blocking(infd) < 0){

            fmt_logln(LOGFP, "failed new conn non block");

            exit(EXIT_FAILURE);
        }

        int res = set_sockctx_by_fd(infd);

        if(res < 0){

            fmt_logln(LOGFP, "failed new conn sockctx");

            exit(EXIT_FAILURE);

        }

        struct SOCK_CONTEXT* sockctx = get_sockctx_by_fd(infd);

        if(sockctx == NULL){

            fmt_logln(LOGFP, "failed new conn sockctx");

            exit(EXIT_FAILURE);

        }

        sockctx->ctx = ctx;
        sockctx->ssl = ssl;
        sockctx->auth = 0;

        

        SOCK_EVENT.data.fd = infd;
        SOCK_EVENT.events = EPOLLIN | EPOLLET;

        if (epoll_ctl(SOCK_EPLFD, EPOLL_CTL_ADD, infd, &SOCK_EVENT) < 0){

            fmt_logln(LOGFP,"handle epoll add failed");  

            

            exit(EXIT_FAILURE);

        }  else {

            fmt_logln(LOGFP,"handle epoll add success"); 

        }


    }



}



void sock_handle_client(int cfd){


    pthread_mutex_lock(&G_MTX);

    struct SOCK_CONTEXT* sockctx = get_sockctx_by_fd(cfd);


    if(sockctx == NULL){
        
        pthread_mutex_unlock(&G_MTX);

        return;
    }


    if(sockctx->auth == 0){

        sock_authenticate(cfd);

        

        pthread_mutex_unlock(&G_MTX);

        return;
    }

    

    int chan_idx = get_sockctx_chan_id_by_fd(cfd);

    if(chan_idx < 0){

        sock_register(cfd);

        pthread_mutex_unlock(&G_MTX);

        return;
    }

    sock_communicate(chan_idx, cfd);

    pthread_mutex_unlock(&G_MTX);

    return;

}



void sock_authenticate(int cfd){

    int valread;
    int valwrite;

    struct HUB_PACKET hp;


    uint8_t id[MAX_ID_LEN] = {0};

    struct SOCK_CONTEXT* sockctx = get_sockctx_by_fd(cfd);

    fmt_logln(LOGFP,"not registered to sock ctx, auth"); 

    if(sockctx == NULL){

        fmt_logln(LOGFP,"failed to get sock idx"); 

        return;
    }


    hp.ctx_type = ISSOCK;
    hp.fd = sockctx->sockfd;

    ctx_read_packet(&hp);

    if(hp.flag <= 0){


        fmt_logln(LOGFP,"failed to read sock"); 

        

        free_sockctx(cfd, 1);

        return;

    }
    


    if(strcmp(hp.header, HUB_HEADER_AUTHSOCK) != 0){

        fmt_logln(LOGFP,"not authenticate header: %s", hp.header); 

        

        free_sockctx(cfd, 1);

        return;

    }
    

    int verified = sig_verify(hp.rbuff, CA_CERT);

    if(verified < 1){

        fmt_logln(LOGFP,"invalid signature"); 

        

        free_sockctx(cfd, 1);

        free(hp.rbuff);

        return;

    }

    

    int ret = extract_common_name(id, hp.rbuff);

    if(ret != 1){

        fmt_logln(LOGFP,"invalid id"); 

        

        free_sockctx(cfd, 1);

        free(hp.rbuff);

        return;


    }

    fmt_logln(LOGFP, "id: %s", id);

    free(hp.rbuff);

    ret = set_sockctx_id_by_fd(cfd, id);

    if (ret < 0){

        fmt_logln(LOGFP, "failed to set sockctx");

        

        free_sockctx(cfd, 1);

        free(hp.rbuff);

        return;

    }

    sockctx->auth = 1;

    

    uint64_t body_len = strlen("SUCCESS") + 1;

    memset(hp.header, 0, HUB_HEADER_BYTELEN);

    memset(hp.wbuff, 0, MAX_BUFF);

    hp.ctx_type = ISSOCK;

    strcpy(hp.header, HUB_HEADER_AUTHSOCK);

    hp.body_len = body_len;

    strcat(hp.wbuff,"SUCCESS");

    strcpy(hp.id, id);

    fmt_logln(LOGFP, "writing auth result..");
    
    ctx_write_packet(&hp);

    if(hp.flag <= 0){

        fmt_logln(LOGFP, "failed to send");

        return;

    }

    fmt_logln(LOGFP, "auth success sent");

    return;


}


void sock_register(int cfd){


    int valread;
    int valwrite;

    int result;

    int is_create;

    struct HUB_PACKET hp;


    uint8_t id[MAX_ID_LEN] = {0};

    struct SOCK_CONTEXT *sockctx = get_sockctx_by_fd(cfd);

    fmt_logln(LOGFP,"not registered to sock ctx, register"); 

    if(sockctx == NULL){

        fmt_logln(LOGFP,"failed to get sock idx"); 

        return;
    }


    hp.ctx_type = ISSOCK;
    hp.fd = sockctx->sockfd;
    
    ctx_read_packet(&hp);

    if(hp.flag <= 0){


        fmt_logln(LOGFP,"failed to read sock"); 

        

        free_sockctx(cfd, 1);

        return;

    }
    

    if(strcmp(hp.header, HUB_HEADER_REGSOCK_CREATE) == 0){

        is_create = 1;

        memcpy(id, hp.rbuff, MAX_ID_LEN);

        result = set_chanctx_by_id(id, 1, cfd);

    } else if (strcmp(hp.header, HUB_HEADER_REGSOCK_JOIN) == 0){

        is_create = 0;

        memcpy(id, hp.rbuff, MAX_ID_LEN);

        result = set_chanctx_by_id(id, 0, cfd);

    } else {

        fmt_logln(LOGFP,"not register header: %s", hp.header); 

        

        free_sockctx(cfd, 1);

        return;

    }
    

    if (result < 0){

        fmt_logln(LOGFP,"failed to register: result: %d", result); 

        

        free_sockctx(cfd, 1);

        return;
    }


    uint64_t body_len = strlen("SUCCESS") + 1;

    memset(hp.header, 0, HUB_HEADER_BYTELEN);

    memset(hp.wbuff, 0, MAX_BUFF);

    hp.ctx_type = ISSOCK;

    if(is_create == 1){

        strcpy(hp.header, HUB_HEADER_REGSOCK_CREATE);

    } else {

        strcpy(hp.header, HUB_HEADER_REGSOCK_JOIN);
    }


    hp.body_len = body_len;

    strcat(hp.wbuff,"SUCCESS");

    strcpy(hp.id, id);

    fmt_logln(LOGFP, "writing auth result..");
    
    ctx_write_packet(&hp);

    if(hp.flag <= 0){

        fmt_logln(LOGFP, "failed to send");

        

        return;

    }

    sockctx->chan_idx = result;

    fmt_logln(LOGFP, "register success sent");

    return;

}


void sock_communicate(int chan_idx, int cfd){

    fmt_logln(LOGFP, "incoming sock communication ");

    struct HUB_PACKET hp;

    hp.fd = -1;

    struct SOCK_CONTEXT* sockctx = get_sockctx_by_fd(cfd);

    if(sockctx == NULL){

        fmt_logln(LOGFP, "failed to get sockctx");

        return;

    }

    hp.ctx_type = ISSOCK;

    hp.fd = sockctx->sockfd;

    ctx_read_packet(&hp);

    if(hp.flag <= 0){

        fmt_logln(LOGFP, "failed to communicate sock read");

    
        return;

    }

    memset(hp.header, 0, HUB_HEADER_BYTELEN);

    memset(hp.wbuff, 0, MAX_BUFF);

    hp.ctx_type = ISSOCK;

    //strcpy(hp.header, HUB_HEADER_RECVFRONT);

    hp.flag = 0;

    int counter = CHAN_CTX[chan_idx].fd_ptr;

    int idlen = strlen(sockctx->id);

    if(idlen + 2 + hp.body_len > MAX_BUFF){

        fmt_logln(LOGFP, "total buf too long: id: %s", sockctx->id);

        

        return;

    }

    memset(hp.wbuff, 0, MAX_BUFF);

    strncat(hp.wbuff, sockctx->id, idlen);

    strcat(hp.wbuff,": ");

    strncat(hp.wbuff, hp.rbuff, hp.body_len);

    hp.body_len = idlen + 2 + hp.body_len;

    free(hp.rbuff);

    // TODO:
    //  invalid if client gone
    //  use reallocate

    for(int i = 0; i < counter; i++){

        int peerfd = CHAN_CTX[chan_idx].fds[i];

        struct SOCK_CONTEXT* peerctx = get_sockctx_by_fd(peerfd);

        if(peerctx == NULL){

            fmt_logln(LOGFP, "failed to send to peer: no peer for: %d", peerfd);

            continue;

        }

        hp.fd = peerfd;

        ctx_write_packet(&hp);

        if(hp.flag <= 0){

            fmt_logln(LOGFP, "failed to send to peer: %d", i);

            continue;
        } 

    }

    
    fmt_logln(LOGFP, "sent to peer");

    return;
}