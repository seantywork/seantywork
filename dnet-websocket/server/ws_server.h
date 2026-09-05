#ifndef _WS_SERVER_H_
#define _WS_SERVER_H_

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> /* for sleep() */



#include "civetweb.h"


/* Global options for this example. */
extern char WS_URL[];
extern char *SERVER_OPTIONS[];

/* Define websocket sub-protocols. */
/* This must be static data, available between mg_start and mg_stop. */
extern char subprotocol_bin[];
extern char subprotocol_json[];
extern char *subprotocols[];
extern struct mg_websocket_subprotocols wsprot;


/* Exit flag for the server */
extern int g_exit;


/* User defined data structure for websocket client context. */
struct tClientContext {
	uint32_t connectionNumber;
	uint32_t demo_var;
};

int ws_connect_handler(const struct mg_connection *conn, void *user_data);

void ws_ready_handler(struct mg_connection *conn, void *user_data);



int ws_data_handler(struct mg_connection *conn,
                int opcode,
                char *data,
                size_t datasize,
                void *user_data);


void ws_close_handler(const struct mg_connection *conn, void *user_data);


#endif