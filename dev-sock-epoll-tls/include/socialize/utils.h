#ifndef _SOCIALIZE_UTILS_H_
#define _SOCIALIZE_UTILS_H_



#include "socialize/core.h"


#define MAX_TIMESTR_LEN 80
#define MAX_LOG_TXT_LEN 1024 
#define MAX_FMT_ARG_LEN 128


int read_file_to_buffer(uint8_t* buff, int max_buff_len, char* file_path);

int gen_random_bytestream(uint8_t* bytes, size_t num_bytes);

int bin2hex(uint8_t* hexarray, int arrlen, uint8_t* bytearray);


int get_host_port(char* hostname, int* port, char* addr);



void get_current_time_string(char* tstr);

void sleepms(long ms);

#define fmt_logln(fp, fmt, ...) _fmt_logln(fp,__FILE__, __LINE__, fmt,  ##__VA_ARGS__)

void _fmt_logln(FILE *fp, char* file, int line, char* fmt_out, ...);


#endif
