#ifndef _CAT_H_
#define _CAT_H_


#include <stdio.h>
#include <stdlib.h>
#include <string.h>


typedef enum BITCAT_FLAG {

    EARG,
    GETFP,

} BITCAT_FLAG;


typedef struct BITCAT_TARGET {

    char* file_path;

} BITCAT_TARGET;






BITCAT_FLAG BITCAT_FlagParser(BITCAT_TARGET* bc_t, int argc, char** argv);

int BITCAT_GetFileIntoBuffer(char** buff, char* file_path);



void BITCAT_PrintBuffer(char* buff);


#endif