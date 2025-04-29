#include "ncat.h"

pthread_mutex_t no_locker;
NCAT_OPTIONS ncat_opts;
char* serve_content = NULL;
int _exit_prog = 0;

int main(int argc, char** argv){



    if(argc < 2){
        fprintf(stderr, "too few arguments\n");
        return -1;
    }

    if(signal(SIGINT, NCAT_keyboard_interrupt) == SIG_ERR){

        fprintf(stderr, "failed to add interrupt handler\n");
        return -1;

    }

    pthread_mutex_init(&no_locker, NULL);

    int parsed = NCAT_parse_args(argc - 1, &argv[1]);

    if(parsed < 0){

        fprintf(stderr, "failed to parse arg\n");

        NCAT_free();

        return parsed;

    }

    ncat_opts._client_sock_ready = 0;
    ncat_opts._client_sockfd = -1;


    int result = NCAT_runner();

    if(result < 0){

        fprintf(stderr, "failed to run command\n");

        NCAT_free();

        return result;

    }



    return 0;
}