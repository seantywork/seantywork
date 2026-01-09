#include "cat.h"


int main(int argc, char** argv){


    BITCAT_TARGET bc_t;

    BITCAT_FLAG flag = BITCAT_FlagParser(&bc_t, argc, argv);

    //TARGET flag = EARG;

    int status = 0;

    char* buff;

    switch(flag){

        case EARG:

            fputs("wrong argument\n", stderr);

            return -1;

        case GETFP:


            status = BITCAT_GetFileIntoBuffer(&buff, bc_t.file_path);

            if(status < 0){

                fputs("error\n",stderr);

                return status;

            }

            BITCAT_PrintBuffer(buff);

            break;
    }

    free(bc_t.file_path);


    free(buff);


    return 0;
}