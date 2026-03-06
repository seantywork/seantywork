
#ifndef _C_STREAM_H_
#define _C_STREAM_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_CHAR_ARR_LEN 1024

#define MAX_STREAM_LEN 1024 * 1024 
#define MAX_ROW_LEN 1024 

void StreamTo2dInterface();

void Print2dBufferFromStream(char* source);

#define MAX_ROW_NUM 128

void StreamTo2dCopyInterface();
void Print2dBufferFromBuffer(char* source);
char** Copy2dBufferFromBuffer(int rowc, char** source); 
void Copy2dBufferFromBuffer2(int rowc, char*** dest, char** source); 


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