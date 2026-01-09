#ifndef _C_STRUCT_H_
#define _C_STRUCT_H_


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>


#define MAX_MEMBER_ARR_LEN 1024


#define MAX_CHAR_ARR_LEN 1024

#define MAX_ROW_NUM 128

void StructCopyThreadInterface();

void* StructCopyThreadForSarr (void* targ);

void* StructCopyThreadForSptr (void* targ);

struct StructWithArr{

    int name;
    char comment[MAX_MEMBER_ARR_LEN];
};


struct StructWithPtr{

    int name;
    char* comment;

};




struct StructWith2dArr{

    int name;
    char first_line_arr[MAX_CHAR_ARR_LEN]; 
    char* first_line_ptr; 
    char* td_buff[MAX_ROW_NUM]; 
    char** dd_buff; 
};

void StreamTo2dStructInterface();
void Print2dBufferFromStruct(char* source);



#endif

