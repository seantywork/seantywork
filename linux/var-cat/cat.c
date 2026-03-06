
#include "cat.h"


BITCAT_FLAG BITCAT_FlagParser(BITCAT_TARGET* bc_t, int argc, char** argv){

    int status = 0;

    if(argc != 2){

        return EARG;

    }


    int file_path_len = strlen(argv[1]) + 1;



    bc_t->file_path = (char*)malloc(file_path_len * sizeof(char));

    memset(bc_t->file_path, 0, file_path_len * sizeof(char));

    strcpy(bc_t->file_path, argv[1]);


    return GETFP;
}



int BITCAT_GetFileIntoBuffer(char** buff, char* file_path){




    int valread = 0;

    FILE* fp;

    fp = fopen(file_path, "r");

    if (fp == NULL){

        return -1;

    }



    if (fseek(fp, 0L, SEEK_END) == 0) {

        long bufsize = ftell(fp);

        if (bufsize == -1) { 
            return -2;
        }



        if (fseek(fp, 0L, SEEK_SET) != 0) { 
            return -3;
        }


        *buff = (char*)malloc(bufsize * sizeof(char));


        memset(*buff, 0, bufsize * sizeof(char));


        size_t read_len = fread(*buff, sizeof(char), bufsize, fp);

        if ( ferror( fp ) != 0 ) {

            return -4;

        } else {

            valread = (int)read_len;

        }
    }
    fclose(fp);

    return valread;
}


void BITCAT_PrintBuffer(char* buff){


    fputs(buff,stdout);

}