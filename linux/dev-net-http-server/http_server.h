#ifndef _HTTP_SERVER_H_
#define _HTTP_SERVER_H_


#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cJSON.h"
#include "civetweb.h"

#define PORT "8089"
#define HOST_INFO "http://localhost:8089"

#define EXAMPLE_URI "/res/*/*"
#define EXIT_URI "/exit"


int SendJSON(struct mg_connection *conn, cJSON *json_obj);

int RestGET(struct mg_connection *conn, const char *p1, const char *p2);

int RestHandler(struct mg_connection *conn, void *cbdata);

int ExitHandler(struct mg_connection *conn, void *cbdata);

int log_message(const struct mg_connection *conn, const char *message);


extern int exitNow;
extern unsigned request;

#endif
