#ifndef _WS_CLIENT_H_
#define _WS_CLIENT_H_


#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "civetweb.h"


struct tclient_data {

	time_t started;
	time_t closed;
	struct tmsg_list_elem *msgs;
};

struct tmsg_list_elem {
	time_t timestamp;
	void *data;
	size_t len;
	struct tmsg_list_elem *next;
};

const char *msgtypename(int flags);


int websocket_client_data_handler(struct mg_connection *conn,
                              int flags,
                              char *data,
                              size_t data_len,
                              void *user_data);

void websocket_client_close_handler(const struct mg_connection *conn,
                               void *user_data);


void run_websocket_client(const char *host,
                     int port,
                     int secure,
                     const char *path,
                     const char *greetings);



#endif