#ifndef _GREP_H_
#define _GREP_H_



#include <stdio.h>
#include <stdlib.h>
#include <string.h>



#define MAX_STDINPUT_WIDTH 1024 * 1024

typedef enum BITGREP_FLAG {

    FIND,
    EARG,

} BITGREP_FLAG;



typedef struct BITGREP_TARGET {

    char* target_string;

} BITGREP_TARGET;


typedef struct BITGREP_INPUT2D{

    int row_count;

    char** buff_2d;

} BITGREP_INPUT2D;


typedef struct BITGREP_FOUND{

    int found_count;

    int* found_index;

    char** buff_found;


} BITGREP_FOUND;





BITGREP_FLAG BITGREP_FlagParser(BITGREP_TARGET* bg_t, int argc, char** argv);



int BITGREP_MapStdinTo2d(BITGREP_INPUT2D* bg_in2d);


int BITGREP_PushBackString(int rowc, char*** vec, char* new_el);

int BITGREP_PushBackInt(int count, int** vec, int new_el);

int BITGREP_PopulateSearchResult(char* target, BITGREP_INPUT2D* bg_in2d, BITGREP_FOUND* bg_found);


void BITGREP_PrintFound(BITGREP_FOUND* bg_found);


void BITGREP_Clear(BITGREP_TARGET* bg_t, BITGREP_INPUT2D* bg_in2d, BITGREP_FOUND* bg_found);






#endif