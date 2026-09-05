#include "socialize/cli/cli.h"
#include "socialize/utils.h"

int cli_done = 0;
int TEST_CASE = -1;
char* CERT_LOC = NULL;


static void signal_handler(int sig){


    cli_done = 1;

}

int main(int argc, char **argv){



    signal(SIGINT, signal_handler);

    int ret;

    if(argc != 3){

        printf("feed arguments\n");

        printf("addr:port number | cert location\n");

        return -1;


    } else {

        if(strcmp(argv[2], "1") == 0){

            TEST_CASE = 1;

            ret = run_cli(argv[1]);

        } else if (strcmp(argv[2], "2") == 0){

            TEST_CASE = 2;

            ret = run_cli(argv[1]);

        } else {

            CERT_LOC = argv[2];

            ret = run_cli(argv[1]);

        }

    }

    return ret;
}