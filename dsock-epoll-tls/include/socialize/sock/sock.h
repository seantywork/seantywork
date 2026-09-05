#ifndef _SOCIALIZE_HUB_SOCK_H_
#define _SOCIALIZE_HUB_SOCK_H_



#include "socialize/core.h"

int init_all();

int free_all();

void sock_listen_and_serve(void* varg);


void sock_handle_conn();


void sock_handle_client(int cfd);

void sock_authenticate(int cfd);

void sock_register(int cfd);

void sock_communicate(int chan_idx, int sock_idx);

#endif