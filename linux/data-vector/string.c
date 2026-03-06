#include "c_vector.h"


/*
int DYNAMICPUSH_PushBackString(int rowc, char*** vec, char* new_el){

    int origin_row_count = rowc;

    int new_row_count = origin_row_count + 1;

    char** vec_tmp = (char**)malloc(new_row_count * sizeof(char*));

    for(int i = 0; i < origin_row_count; i ++){

        int line_len = strlen((*vec)[i]) + 1;

        vec_tmp[i] = (char*)malloc(line_len * sizeof(char) + 1);

        memset(vec_tmp[i], 0 , line_len * sizeof(char) + 1);

        strcpy(vec_tmp[i], (*vec)[i]);

        free((*vec)[i]);

       //printf("[ COPIED %d ] %s\n", i, vec_tmp[i]);

    }

    int new_line_len = strlen(new_el);

    vec_tmp[origin_row_count] = (char*)malloc(new_line_len * sizeof(char) + 1);

    memset(vec_tmp[origin_row_count], 0 , new_line_len * sizeof(char) + 1);

    strcpy(vec_tmp[origin_row_count], new_el);

    if(origin_row_count != 0){
        free(*vec);
    }

    *vec = vec_tmp;


    return 0;
}

int DYNAMICPUSH_PushBackInt(int count, int** vec, int new_el){

    int origin_el_count = count;

    int new_el_count = origin_el_count + 1;

    int* vec_tmp = (int*)malloc(new_el_count * sizeof(int));

    for(int i = 0; i < origin_el_count; i ++){


        vec_tmp[i] = (*vec)[i];

       //printf("[ COPIED %d ] %s\n", i, vec_tmp[i]);

    }

    vec_tmp[origin_el_count] = new_el;
   
    if(origin_el_count != 0){
        free(*vec);
    }

    *vec = vec_tmp;


    return 0;
}


*/




int VECTOR_PushBackString(int rowc, char*** vec, char* new_el){

    int origin_row_count = rowc;

    int new_row_count = origin_row_count + 1;

    char** vec_tmp;

    if(origin_row_count == 0){

        vec_tmp = (char**)malloc(new_row_count * sizeof(char*));


    } else if(origin_row_count != 0) {


        vec_tmp = (char**)realloc(*vec, new_row_count * sizeof(char*));


    }

    int new_line_len = strlen(new_el);

    vec_tmp[origin_row_count] = (char*)malloc(new_line_len * sizeof(char) + 1);

    memset(vec_tmp[origin_row_count], 0 , new_line_len * sizeof(char) + 1);

    strcpy(vec_tmp[origin_row_count], new_el);

    *vec = vec_tmp;

    return 0;
}


int VECTOR_EraseString(int rowc, char*** vec, int index){

    int origin_row_count = rowc;

    int new_row_count = origin_row_count - 1;

    if (new_row_count < 0){

        return -1;
    }

    if(index >= origin_row_count || index < 0 ){

        return -2;
    }

    for(int i = 0 ; i < rowc; i ++){

        if(i < index){

            continue;

        } else if( i == index){

            free((*vec)[i]);

            continue;

        } else if (i > index && i != (rowc - 1)){

            (*vec)[i - 1] = (*vec)[i]; 

            continue;

        } else if (i > index && i == (rowc - 1)){

            int last_strlen = strlen((*vec)[i]) + 1;

            char* new_last = (char*)malloc(last_strlen * sizeof(char));

            memset(new_last, 0 , last_strlen * sizeof(char));

            strcpy(new_last, (*vec)[i]);

            free((*vec)[i]);

            (*vec)[i - 1] = new_last;
        }

    }


    if(new_row_count == 0){

        free(*vec);

        return 1;
    }

    char** new_vec;

    new_vec = (char**)realloc(*vec, new_row_count * sizeof(char*));

    *vec = new_vec;

    return 0;
}