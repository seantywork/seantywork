#ifndef _SOCIALIZE_CTL_H_
#define _SOCIALIZE_CTL_H_

#include "socialize/core.h"


int make_socket_non_blocking (int sfd);

SSL_CTX *create_context();

void configure_context(SSL_CTX *ctx);


int sig_verify(const char* cert_pem, const char* intermediate_pem);

int extract_common_name(uint8_t* common_name, const char* cert);

int idpw_verify(char* idpw, char* newid, uint8_t* newtoken);


int make_hash(int fd, int buck_size);

int set_sockctx_by_fd(int fd);

struct SOCK_CONTEXT* get_sockctx_by_fd(int fd);

int set_sockctx_id_by_fd(int fd, char* id);

int get_sockctx_id_by_fd(int fd, char* id);

int set_chanctx_by_id(char* id, int create, int fd);

int get_chanctx_by_id(char* id);

int set_sockctx_chan_id_by_fd(int fd, int chan_id);

int get_sockctx_chan_id_by_fd(int fd);



int calloc_chanctx();

int free_chanctx(int idx);

int calloc_sockctx(int fd);

int free_sockctx(int fd, int memfree);





int sockctx_write(int fd, int write_len, uint8_t* wbuff);

int sockctx_read(int fd, int read_len, uint8_t* rbuff);




void ctx_write_packet(struct HUB_PACKET* hp);


void ctx_read_packet(struct HUB_PACKET* hp);


void spinlock_init(struct spinlock* spinlock);

void spinlock_lock(struct spinlock* spinlock);

void spinlock_unlock(struct spinlock* spinlock);


#endif