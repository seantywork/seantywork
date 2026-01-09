#ifndef _HTTP_REQ_H_
#define _HTTP_REQ_H_



#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 
#include <stdint.h>
#include <curl/curl.h>


size_t req_write_callback(void *data, size_t size, size_t nmemb, void *clientp);

int request_get(char* result, char* req_url);

int request_post(char* result, char* req_url, char* code);


#endif