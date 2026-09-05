#include "socialize/ctl.h"
#include "socialize/utils.h"


// TODO:
//  rehashing


int make_socket_non_blocking (int sfd){
    int flags, s;

    flags = fcntl (sfd, F_GETFL, 0);
    if (flags == -1)
    {
        perror ("fcntl get");
        return -1;
    }

    flags |= O_NONBLOCK;
    s = fcntl (sfd, F_SETFL, flags);
    if (s == -1)
    {
        perror ("fcntl set");
        return -2;
    }

    return 0;
}


SSL_CTX *create_context(){

    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx){

    if (SSL_CTX_use_certificate_file(ctx, SERVER_CERT, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY, SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

int sig_verify(const char* cert_pem, const char* intermediate_pem){

    BIO *b = BIO_new(BIO_s_mem());
    BIO_puts(b, intermediate_pem);
    X509 * issuer = PEM_read_bio_X509(b, NULL, NULL, NULL);
    EVP_PKEY *signing_key=X509_get_pubkey(issuer);
 
    BIO *c = BIO_new(BIO_s_mem());
    BIO_puts(c, cert_pem);
    X509 * x509 = PEM_read_bio_X509(c, NULL, NULL, NULL);
 
    int result = X509_verify(x509, signing_key);
 
    EVP_PKEY_free(signing_key);
    BIO_free(b);
    BIO_free(c);
    X509_free(x509);
    X509_free(issuer);
 
    return result;
}

int extract_common_name(uint8_t* common_name, const char* cert) {

    BIO *b = BIO_new(BIO_s_mem());
    BIO_puts(b, cert);
    X509 * x509 = PEM_read_bio_X509(b, NULL, NULL, NULL);

    int ret_cn = -1;

    int common_name_loc = X509_NAME_get_index_by_NID(X509_get_subject_name(x509), NID_commonName, -1);
    if (common_name_loc < 0) {
        BIO_free(b);
        X509_free(x509);
        return ret_cn;
    }
    
    X509_NAME_ENTRY * common_name_entry = X509_NAME_get_entry(X509_get_subject_name(x509), common_name_loc);
    if (common_name_entry == NULL) {
        BIO_free(b);
        X509_free(x509);
        return ret_cn;
    }
    
    ASN1_STRING * common_name_asn1 = X509_NAME_ENTRY_get_data(common_name_entry);
    if (common_name_asn1 == NULL) {
        BIO_free(b);
        X509_free(x509);
        return ret_cn;
    }
    
    char const * common_name_str = (char const *) ASN1_STRING_get0_data(common_name_asn1);
    
    if (ASN1_STRING_length(common_name_asn1) != strlen(common_name_str)) {
        BIO_free(b);
        X509_free(x509);
        return ret_cn;
    }

    strcpy(common_name, common_name_str);

    ret_cn = 1;
    
    BIO_free(b);
    X509_free(x509);

    return ret_cn;
}



static inline uint32_t _fnv(uint8_t* data, size_t size){

	size_t nblocks = size / 8;
	uint64_t hash = 2166136261u;
	for (size_t i = 0; i < nblocks; ++i){
		hash ^= (uint64_t)data[0] << 0 | (uint64_t)data[1] << 8 |
			 (uint64_t)data[2] << 16 | (uint64_t)data[3] << 24 |
			 (uint64_t)data[4] << 32 | (uint64_t)data[5] << 40 |
			 (uint64_t)data[6] << 48 | (uint64_t)data[7] << 56;
		hash *= 0xbf58476d1ce4e5b9;
		data += 8;
	}

	uint64_t last = size & 0xff;
	switch (size % 8){
	case 7:
		last |= (uint64_t)data[6] << 56; /* fallthrough */
	case 6:
		last |= (uint64_t)data[5] << 48; /* fallthrough */
	case 5:
		last |= (uint64_t)data[4] << 40; /* fallthrough */
	case 4:
		last |= (uint64_t)data[3] << 32; /* fallthrough */
	case 3:
		last |= (uint64_t)data[2] << 24; /* fallthrough */
	case 2:
		last |= (uint64_t)data[1] << 16; /* fallthrough */
	case 1:
		last |= (uint64_t)data[0] << 8;
		hash ^= last;
		hash *= 0xd6e8feb86659fd93;
	}

	//return (uint32_t)(hash ^ hash >> 32);
	return hash;
}

static inline uint32_t _hashfunc(uint8_t* data, size_t size){
	uint32_t hashtrunc = 0;
	uint8_t hash[32] = {0};
	EVP_MD_CTX *mdctx;
	int digest_len = 0;
	mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
	EVP_DigestUpdate(mdctx, data, size);
	EVP_DigestFinal_ex(mdctx, hash, &digest_len);
	EVP_MD_CTX_free(mdctx);
	memcpy(&hashtrunc, hash, sizeof(uint32_t));
    return hashtrunc;
}

int make_hash(int fd, int buck_size){

    uint32_t hash = _hashfunc((uint8_t*)&fd, sizeof(int));

    return hash % buck_size;
}


int set_sockctx_by_fd(int fd){


    int new_idx = calloc_sockctx(fd);

    if(new_idx < 0){


        return -1;

    }

    return 0;
}




struct SOCK_CONTEXT* get_sockctx_by_fd(int fd){

    //struct SOCK_CONTEXT* ctx = (struct SOCK_CONTEXT*)malloc(sizeof(struct SOCK_CONTEXT));

    //memset(ctx, 0, sizeof(struct SOCK_CONTEXT));

    struct SOCK_CONTEXT* ctx;

    struct SOCK_CONTEXT_LOCK* ctxlock;

    pthread_mutex_lock(&SOCK_CTL.slock);

    if(SOCK_CTL.in_use == 0){

        printf("sockctl not in use\n");

        pthread_mutex_unlock(&SOCK_CTL.slock);

        return NULL;
    }

    int i = make_hash(fd, SOCK_CTL.size);

    ctx = SOCK_CTL.SOCK_CTX[i];

    ctxlock = SOCK_CTL.SOCK_CTX_LOCK[i];

    pthread_mutex_unlock(&SOCK_CTL.slock);

    pthread_mutex_lock(&ctxlock->lock);

    while(ctx != NULL){

        if(ctx->sockfd == fd){

            pthread_mutex_unlock(&ctxlock->lock);

            return ctx;

        }

        ctx = ctx->next;

    }

    pthread_mutex_unlock(&ctxlock->lock);


    //free(ctx);

    return NULL;
}


int set_sockctx_id_by_fd(int fd, char* id){

    struct SOCK_CONTEXT* ctx = get_sockctx_by_fd(fd);

    if(ctx == NULL){

        return -1;
    }

    memcpy(ctx->id, id, MAX_ID_LEN);


    return 0;
}

int get_sockctx_id_by_fd(int fd, char* id){


    struct SOCK_CONTEXT* ctx = get_sockctx_by_fd(fd);

    if(ctx == NULL){

        return -1;
    }

    memcpy(id, ctx->id, MAX_ID_LEN);

    return 0;

}



int set_chanctx_by_id(char* id, int create, int fd){

    int idx = get_chanctx_by_id(id);

    if(create == 1){

        if(idx < 0){

            idx = calloc_chanctx();

            memcpy(CHAN_CTX[idx].id, id, MAX_ID_LEN);

            CHAN_CTX[idx].fds[CHAN_CTX[idx].fd_ptr] = fd;

            CHAN_CTX[idx].fd_ptr += 1;

        } else {

            return -1;
        }


    } else {


        if(idx < 0){

            return -2;

        } else {

            CHAN_CTX[idx].fds[CHAN_CTX[idx].fd_ptr] = fd;
            CHAN_CTX[idx].fd_ptr += 1;
        }


    }


    return idx;


}


int get_chanctx_by_id(char* id){


    for(int i = 0; i < MAX_CONN; i++){

        if(strcmp(CHAN_CTX[i].id, id) == 0){

            return i;

        }

    }


    return -1;
}



int set_sockctx_chan_id_by_fd(int fd, int chan_id){


    struct SOCK_CONTEXT* ctx = get_sockctx_by_fd(fd);

    if(ctx == NULL){

        return -1;
    }

    ctx->chan_idx = chan_id;

    return 0;

}




int get_sockctx_chan_id_by_fd(int fd){


    struct SOCK_CONTEXT* ctx = get_sockctx_by_fd(fd);

    if(ctx == NULL){

        return -1;
    }

    int chan_idx = ctx->chan_idx;


    return chan_idx;

}



int calloc_chanctx(){


    for(int i = 0; i < MAX_CONN; i++){


        if(CHAN_CTX[i].allocated == 0){

            CHAN_CTX[i].allocated = 1;

            CHAN_CTX[i].sockfd = 0;
            CHAN_CTX[i].frontfd = 0;

            memset(CHAN_CTX[i].id, 0, MAX_ID_LEN * sizeof(char));
            memset(CHAN_CTX[i].pw, 0, MAX_PW_LEN * sizeof(char));        

            CHAN_CTX[i].ssl = NULL;
            CHAN_CTX[i].ctx = NULL;


            return i;

        }

    }


    return -1;
}


int free_chanctx(int idx){

    if(idx >= MAX_CONN){

        return -10;
    }

    if(CHAN_CTX[idx].allocated != 1){

        return -1;

    }

    if (CHAN_CTX[idx].ssl != NULL){

        SSL_shutdown(CHAN_CTX[idx].ssl);
        SSL_free(CHAN_CTX[idx].ssl);

    }

    if (CHAN_CTX[idx].ctx != NULL){

        SSL_CTX_free(CHAN_CTX[idx].ctx);

    }

    CHAN_CTX[idx].sockfd = 0;
    CHAN_CTX[idx].frontfd = 0;


    memset(CHAN_CTX[idx].id, 0, MAX_ID_LEN * sizeof(char));
    memset(CHAN_CTX[idx].pw, 0, MAX_PW_LEN * sizeof(char));   

    CHAN_CTX[idx].ssl = NULL;
    CHAN_CTX[idx].ctx = NULL;

    CHAN_CTX[idx].allocated = 0;

    return 0;
}


int calloc_sockctx(int fd){


    struct SOCK_CONTEXT* ctx = NULL;

    struct SOCK_CONTEXT_LOCK* ctxlock = NULL;

    pthread_mutex_lock(&SOCK_CTL.slock);

    if(SOCK_CTL.in_use == 0){

        printf("sockctl not in use\n");

        pthread_mutex_unlock(&SOCK_CTL.slock);

        return -1;
    }

    int i = make_hash(fd, SOCK_CTL.size);

    ctx = SOCK_CTL.SOCK_CTX[i];

    ctxlock = SOCK_CTL.SOCK_CTX_LOCK[i];

    pthread_mutex_unlock(&SOCK_CTL.slock);

    pthread_mutex_lock(&ctxlock->lock);

    while(ctx != NULL){

        if(ctx->allocated == 0){

            ctx->ctx = NULL;
            ctx->ssl = NULL;
            ctx->sockfd = fd;
            ctx->chan_idx = -1;
            ctx->allocated = 1;

            pthread_mutex_unlock(&ctxlock->lock);

            return i;

        }

        ctx = ctx->next;

    }

    pthread_mutex_unlock(&ctxlock->lock);

    return -1;
}



int free_sockctx(int fd, int memfree){


    struct SOCK_CONTEXT* ctx = NULL;

    struct SOCK_CONTEXT_LOCK* ctxlock = NULL;

    pthread_mutex_lock(&SOCK_CTL.slock);

    if(SOCK_CTL.in_use == 0){

        printf("sockctl not in use\n");

        pthread_mutex_unlock(&SOCK_CTL.slock);

        return -1;
    }


    int i = make_hash(fd, SOCK_CTL.size);

    ctx = SOCK_CTL.SOCK_CTX[i];

    ctxlock = SOCK_CTL.SOCK_CTX_LOCK[i];

    pthread_mutex_unlock(&SOCK_CTL.slock);

    pthread_mutex_lock(&ctxlock->lock);

    while(ctx != NULL){

        if(ctx->sockfd == fd){

            if(memfree == 1){

                SSL_shutdown(ctx->ssl);
                SSL_free(ctx->ssl);
                SSL_CTX_free(ctx->ctx);
        
            } else {
        
                ctx->ssl = NULL;
                ctx->ctx = NULL;
        
            }
        
            ctx->sockfd = 0;
            ctx->allocated = 0;

            pthread_mutex_unlock(&ctxlock->lock);

            return 0;
        }

        ctx = ctx->next;

    }

    pthread_mutex_unlock(&ctxlock->lock);

    return -1;
}



int sockctx_write(int fd, int write_len, uint8_t* wbuff){


    int valwrite = 0;

    struct SOCK_CONTEXT* sockctx = NULL;

    sockctx = get_sockctx_by_fd(fd);

    if(sockctx == NULL){

        printf("write: no such fd: %d\n", fd);

        return -1;
    }

    SSL* sslfd = sockctx->ssl;

    valwrite = SSL_write(sslfd, (void*)wbuff, write_len);

    if (valwrite <= 0){

        printf("write: client gone: %d\n", valwrite);

        ;

        return -2;

    }


    return valwrite;


}

int sockctx_read(int fd, int read_len, uint8_t* rbuff){



    int valread = 0;

    int sock_idx = 0;

    int ms_until_deadline = 0;

    struct SOCK_CONTEXT* sockctx = get_sockctx_by_fd(fd);

    if(sockctx == NULL){

        printf("read: no such fd: %d\n", fd);

        return -1;
    }


    SSL* sslfd = sockctx->ssl;

    uint8_t* rbuff_tmp = (uint8_t*)malloc(read_len * sizeof(uint8_t));

    memset(rbuff_tmp, 0, read_len * sizeof(uint8_t));

    int valread_tmp = 0;

    struct timespec rnow;

    clock_gettime(CLOCK_MONOTONIC_RAW, &rnow);

    struct timespec rdeadline;

    // TODO:
    //  simplify

    while(valread < read_len){

        clock_gettime(CLOCK_MONOTONIC_RAW, &rdeadline);

        ms_until_deadline = ((rdeadline.tv_sec - rnow.tv_sec) * 1000 + (rdeadline.tv_nsec - rnow.tv_nsec) / 1000000);

        if(ms_until_deadline > HUB_TIMEOUT_MS){
            
            printf("time limit exceeded\n");


            free(rbuff_tmp);

            return -10;
        }

        valread_tmp = SSL_read(sslfd, (void*)rbuff_tmp, read_len);

        if(valread_tmp <= 0){

            if(errno == EAGAIN){

                memset(rbuff_tmp, 0, read_len * sizeof(uint8_t));

                valread_tmp = 0;

                continue;
            }

            printf("read: client gone: %d\n", valread);


            free(rbuff_tmp);

            return -2;
        }

        for(int i = 0 ; i < valread_tmp; i++){

            int idx = valread + i;

            rbuff[idx] = rbuff_tmp[i];

        }

        valread += valread_tmp;        

        memset(rbuff_tmp, 0, read_len * sizeof(uint8_t));

        valread_tmp = 0;

    }

    free(rbuff_tmp);

    return valread;


}







void ctx_write_packet(struct HUB_PACKET* hp){

    int valwrite = 0;


    if(hp->ctx_type == ISSOCK){

        valwrite = sockctx_write(hp->fd, HUB_HEADER_BYTELEN, hp->header);

        if(valwrite <= 0){

            printf("packet send header failed\n");

            hp->flag = valwrite;

            return;

        }

        uint8_t body_len_byte[HUB_BODY_BYTELEN] = {0};

        uint64_t body_len_new = 0;

        body_len_new = htonll(hp->body_len);

        memcpy(body_len_byte, &body_len_new, HUB_BODY_BYTELEN);

        valwrite = sockctx_write(hp->fd, HUB_BODY_BYTELEN, body_len_byte);

        if(valwrite <= 0){

            printf("packet send body len failed\n");

            hp->flag = valwrite;

            return;

        }

        valwrite = sockctx_write(hp->fd, hp->body_len, hp->wbuff);

        if(valwrite <= 0){

            printf("packet send buff failed\n");

            hp->flag = valwrite;

            return;

        } 

        hp->flag = valwrite;

        return;


    }


    printf("invalid ctx write packet type: %d\n", hp->ctx_type);

    hp->flag = valwrite;


    return;

}


void ctx_read_packet(struct HUB_PACKET* hp){

    int valread = 0;

    if(hp->ctx_type == ISSOCK){

        valread = sockctx_read(hp->fd, HUB_HEADER_BYTELEN, hp->header);

        if(valread <= 0){

            printf("packet recv header failed\n");

            hp->flag = valread;

            return;

        }

        uint8_t body_len_byte[HUB_BODY_BYTELEN] = {0};

        uint64_t body_len = 0;

        valread = sockctx_read(hp->fd, HUB_BODY_BYTELEN, body_len_byte);

        if(valread <= 0){

            printf("packet recv body len failed\n");

            hp->flag = valread;

            return;

        }

        memcpy(&body_len, body_len_byte, HUB_BODY_BYTELEN);

        body_len = ntohll(body_len);

        if(body_len > HUB_BODY_BYTEMAX){

            printf("packet body len too long \n");

            hp->flag = -10;

            return;
        }

        hp->body_len = body_len;

        hp->rbuff = (uint8_t*)malloc(hp->body_len * sizeof(uint8_t));

        memset(hp->rbuff, 0, hp->body_len * sizeof(uint8_t));

        valread = sockctx_read(hp->fd, hp->body_len, hp->rbuff);

        if(valread <= 0){

            printf("packet recv body failed\n");

            free(hp->rbuff);

            hp->flag = valread;

            return;

        }

        hp->flag = valread;

        return;


    }




    printf("invalid ctx read packet type: %d\n", hp->ctx_type);

    hp->flag = valread;

    return;
}






static inline bool atomic_compare_exchange(int* ptr, int compare, int exchange) {
    return __atomic_compare_exchange_n(ptr, &compare, exchange,
            0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
}

static inline void atomic_store(int* ptr, int value) {
    __atomic_store_n(ptr, 0, __ATOMIC_SEQ_CST);
}

static inline int atomic_add_fetch(int* ptr, int d) {
    return __atomic_add_fetch(ptr, d, __ATOMIC_SEQ_CST);
}


void spinlock_init(struct spinlock* spinlock) {
    atomic_store(&spinlock->locked, 0);
}

void spinlock_lock(struct spinlock* spinlock) {
    while (!atomic_compare_exchange(&spinlock->locked, 0, 1)) {
    }
}

void spinlock_unlock(struct spinlock* spinlock) {
    atomic_store(&spinlock->locked, 0);
}
