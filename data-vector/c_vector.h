#ifndef _C_VECTOR_H_
#define _C_VECTOR_H_



#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define MAX_STREAM_LEN 1024 * 1024 

struct VectorString{

    int size;

    char** vector;

};


void PushBackStringInterface();
void PrintPushBackStringStruct(char* source);
struct VectorString* PushBackString(struct VectorString* sv, char* new_str);



struct VectorString* VS_new();
void VS_append(struct VectorString* sv, char* new_str);
void VS_delete(struct VectorString* sv);

// void PushBackString2(struct VectorString* sv, char* new_str);
void PushBackString2(struct VectorString** sv, char* new_str);


void VectorStringInterface();

void PrintReducedVectorString(char* source);


int VECTOR_PushBackString(int rowc, char*** vec, char* new_el);

int VECTOR_EraseString(int rowc, char*** vec, int index);

int VECTOR_PushBackInt(int count, int** vec, int new_el);

int VECTOR_EraseInt(int count, int** vec, int index);



#endif