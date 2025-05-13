#include "iperf_s.h"


char mode = 's';
int port = 5001;
int client_num = 1;
uint8_t client_buff[MAXCLIENT][MAXBUFFLEN];

static void help(){

    printf("arguments: mode port client_num\n");
        
    printf("mode: s - select, p - poll, e - epoll\n");
}

int main(int argc, char** argv){

    int result = -1;


    if(argc != 4){

        help();

        return -1;
    }

    memset(client_buff, 0, MAXCLIENT * MAXBUFFLEN);

    if(strcmp(argv[1], "s") == 0){

        mode = 's';
    } else if(strcmp(argv[1], "p") == 0){

        mode = 'p';
    } else if(strcmp(argv[1], "e") == 0){

        mode = 'e';
    } else {

        printf("invalid mode: %s\n", argv[1]);
        help();

        return -2;
    }

    sscanf(argv[2], "%d", &port);

    printf("port to use: %d\n", port);

    sscanf(argv[3], "%d", &client_num);

    printf("client num: %d\n", client_num);


    if(mode == 's'){

        result = run_select();

    } else if (mode == 'p') {

        result = run_poll();

    } else if (mode == 'e') {

        result = run_epoll();
    }

    return 0;
}