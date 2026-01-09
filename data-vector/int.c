#include "c_vector.h"


int VECTOR_PushBackInt(int count, int** vec, int new_el){

    int origin_el_count = count;

    int new_el_count = origin_el_count + 1;

    int* vec_tmp;

    if(origin_el_count == 0){

        vec_tmp = (int*)malloc(new_el_count * sizeof(int));

    } else if (origin_el_count != 0){

        vec_tmp = (int*)realloc(*vec, new_el_count * sizeof(int));

    }


    vec_tmp[origin_el_count] = new_el;
   
    *vec = vec_tmp;

    return 0;
}


int VECTOR_EraseInt(int count, int** vec, int index){


    int origin_el_count = count;

    int new_el_count = origin_el_count - 1;

    if(new_el_count < 0){
        return -1;
    }

    if (index >= origin_el_count || index < 0){

        return -2;
    }



    for(int i = 0 ; i < count; i ++){

        if(i <= index){

            continue;

        } else if (i > index){

            (*vec)[i - 1] = (*vec)[i]; 

            continue;

        } 
    }

    if(new_el_count == 0){
        
        free(*vec);

        return 1;
    }

    int* new_vec;

    new_vec = (int*)realloc(*vec, new_el_count * sizeof(int));

    *vec = new_vec;


    return 0;
}