#include "socialize/utils.h"


int read_file_to_buffer(uint8_t* buff, int max_buff_len, char* file_path){


    int valread = 0 ;

    int c;

    FILE* fp;

    fp = fopen(file_path, "r");

    while(1) {

        c = fgetc(fp);
        if( feof(fp) ) {
            break;
        }


        buff[valread] = c;

        valread += 1;

        if(valread > max_buff_len){

            return -10;
        }
    
   }

    return valread;
}

int gen_random_bytestream(uint8_t* bytes, size_t num_bytes){
  

    if(num_bytes > MAX_PW_LEN){

        return -1;

    }


    size_t i;

    for (i = 0; i < num_bytes; i++){

        if (0 >getrandom(bytes + i, 1, 0)){
    
          return -2;
        }
      
    }

    return 0;

}

int bin2hex(uint8_t* hexarray, int arrlen, uint8_t* bytearray){

    int hexlen = 2;
    
    int outstrlen = hexlen * arrlen + 1;

    if (outstrlen > MAX_PW_LEN){

        return -1;
    }

    uint8_t* tmparr = (uint8_t*)malloc(outstrlen * sizeof(uint8_t));

    memset(tmparr, 0, outstrlen * sizeof(uint8_t));

    unsigned char* ptr = tmparr;

    for(int i = 0 ; i < arrlen; i++){

        sprintf(ptr + 2 * i, "%02X", bytearray[i]);
    }

    memset(hexarray, 0, outstrlen * sizeof(char));

    memcpy(hexarray, tmparr, outstrlen);


    free(tmparr);

    return 0;
    
}

int get_host_port(char* hostname, int* port, char* addr){

    char addr_cp[MAX_ID_LEN]  = {0};

    char port_str[MAX_ID_LEN] = {0};

    strcpy(addr_cp, addr);

    char* delim = ":";
    char *token;

    token = strtok(addr, delim);

    int idx = 0;

    while(token != NULL) {
    
        if(idx == 0){

            strcpy(hostname, token);

        } else if (idx == 1){


            strcpy(port_str, token);

            sscanf(port_str, "%d", port);

        } else {

            return -1;
        }

        token = strtok(NULL, delim);

        idx += 1;

    }

    if (idx < 2){
        return -2;
    }

    return 0;

}


void get_current_time_string(char* tstr){


    struct tm info;
    
    int millisec;
    char msec_str[5] = {0};

    struct timeval tv;

    gettimeofday(&tv, NULL);

    millisec = tv.tv_usec / 1000;

    if (millisec >= 1000){

        millisec -= 1000;
        tv.tv_sec += 1;

    }

    localtime_r(&tv.tv_sec, &info);

    strftime(tstr, MAX_TIMESTR_LEN, "%Y-%m-%d %H:%M:%S", &info);

    sprintf(msec_str, ".%03d", millisec);

    strcat(tstr, msec_str);

}

void sleepms(long ms){


    struct timespec ts;
    int res;

    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000;

    nanosleep(&ts, &ts);



}


int _log_lock_init = 0;
pthread_mutex_t _log_lock;

static inline void _do_log(FILE *fp, char* file, int line, char* fmt_out, va_list args){

    char log_fmt_str[MAX_LOG_TXT_LEN] = {0};
    char time_str[MAX_TIMESTR_LEN] = {0};

    get_current_time_string(time_str);

    sprintf(log_fmt_str, "[%s][%s:%d] ", time_str, file, line);
    strcat(log_fmt_str, fmt_out);
    strcat(log_fmt_str, "\n");
    vfprintf(fp, log_fmt_str, args);
    fflush(fp);

}

void _fmt_logln(FILE *fp, char* file, int line, char* fmt_out, ...){

    if(!_log_lock_init){
        pthread_mutex_init(&_log_lock, NULL);
        _log_lock_init = 1;
    }

    va_list args;
    pthread_mutex_lock(&_log_lock);
    va_start(args, fmt_out);
    _do_log(fp, file, line, fmt_out, args);
    va_end(args);
    pthread_mutex_unlock(&_log_lock);
}