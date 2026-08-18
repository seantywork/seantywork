#include "c_vector.h"


void PrintPushBackStringStruct(char* source){

    int row_num = 0;

    char* delim = "\n";

    char* s_tmp = source;

    char source_cp[MAX_STREAM_LEN] = {0};

    char source_cpcp[MAX_STREAM_LEN] = {0};

    strcpy(source_cp, source);

    strcpy(source_cpcp, source);

    while(s_tmp != NULL)                                                                                                    
    {                                                                                                                       
        s_tmp = strchr(s_tmp, '\n');                                                                                                           
        if( s_tmp ) {
            s_tmp++;
            row_num++;
        }                                                                                                
    }



    struct VectorString* sv = (struct VectorString*)malloc(sizeof(struct VectorString));
 
    sv->size = 0;

    char* ptk = strtok(source, delim);

    int row = 0;

    printf("row num: %d\n", row_num);

    while(ptk != NULL){

        sv = PushBackString(sv, ptk);

        ptk = strtok(NULL, delim);
                
    }

    printf("vector filled\n");

    row = sv->size;

    printf("row num: %d, row: %d\n", row_num, row);



    for(int i = 0; i < row; i ++){

        printf("[ LINE ]: %s\n", sv->vector[i]);

    }


    printf("[ EOF ]\n");


    for(int i = 0; i < row; i ++){

        free(sv->vector[i]);


    }

    free(sv->vector);
    free(sv);


    struct VectorString* sv2 = VS_new();

    char* ptk2 = strtok(source_cp, delim);

    int row2 = 0;

    printf("row num 2: %d\n", row_num);

    while(ptk2 != NULL){

        VS_append(sv2, ptk2);

        ptk2 = strtok(NULL, delim);
                
    }
    printf("vector filled 2\n");

    row2 = sv2->size;

    printf("row num2: %d, row2: %d\n", row_num, row2);

    for(int i = 0; i < row2; i ++){

        printf("[ LINE 2 ]: %s\n", sv2->vector[i]);

    }


    printf("[ EOF 2 ]\n");

    VS_delete(sv2);




    struct VectorString* sv3 = VS_new();

    char* ptk3 = strtok(source_cpcp, delim);

    int row3 = 0;

    printf("row num 3: %d\n", row_num);

    while(ptk3 != NULL){

        PushBackString2(&sv3, ptk3);
        
        ptk3 = strtok(NULL, delim);
                
    }
    printf("vector filled 3\n");

    row3 = sv3->size;

    printf("row num3: %d, row3: %d\n", row_num, row3);

    for(int i = 0; i < row3; i ++){

        printf("[ LINE 3 ]: %s\n", sv3->vector[i]);

    }


    printf("[ EOF 3 ]\n");

    VS_delete(sv3);

}




struct VectorString* PushBackString(struct VectorString* sv, char* new_str){

    int org_vec_size = sv->size;

    int new_str_len = strlen(new_str);

    int new_vec_size = org_vec_size + 1;

    struct VectorString* new_vec = (struct VectorString*)malloc(sizeof(struct VectorString));

    new_vec->vector = (char**)malloc(new_vec_size * sizeof(char*));

    for(int i = 0 ; i < org_vec_size; i++){

        int line_strlen = strlen(sv->vector[i]) + 1;

        new_vec->vector[i] = (char*)malloc(line_strlen * sizeof(char));

        memset(new_vec->vector[i], 0, line_strlen * sizeof(char));

        strcpy(new_vec->vector[i], sv->vector[i]);

        free(sv->vector[i]);
    }

    if(org_vec_size > 0){

        free(sv->vector);
    }


    free(sv);


    int new_line_strlen = strlen(new_str) + 1;

    new_vec->vector[org_vec_size] = (char*)malloc(new_line_strlen*sizeof(char));

    memset(new_vec->vector[org_vec_size], 0 , new_line_strlen * sizeof(char));

    strcpy(new_vec->vector[org_vec_size], new_str);

    new_vec->size = new_vec_size;


    return new_vec;
}



struct VectorString* VS_new(){


    struct VectorString* new_vec = (struct VectorString*)malloc(sizeof(struct VectorString));

    new_vec->size = 0;

    return new_vec;

}


void VS_append(struct VectorString* sv, char* new_str){


    struct VectorString* set_sv = sv;

    int org_vec_size = set_sv->size;

    int new_vec_size = org_vec_size + 1;

    char** new_vec = (char**)malloc(new_vec_size * sizeof(char*));

    for(int i = 0; i < org_vec_size; i++){

        int line_strlen = strlen(set_sv->vector[i]) + 1;

        new_vec[i] = (char*)malloc(line_strlen * sizeof(char));

        memset(new_vec[i], 0 , line_strlen * sizeof(char));

        strcpy(new_vec[i], set_sv->vector[i]);

        free(set_sv->vector[i]);

    }

    free(set_sv->vector);

    int new_line_strlen = strlen(new_str) + 1;

    new_vec[org_vec_size] = (char*)malloc(new_line_strlen*sizeof(char));

    memset(new_vec[org_vec_size], 0 , new_line_strlen * sizeof(char));

    strcpy(new_vec[org_vec_size], new_str);

    set_sv->vector = new_vec;

    set_sv->size = new_vec_size;


}


void VS_delete(struct VectorString* sv){

    int v_size = sv->size;


    for(int i = 0; i < v_size; i ++){

        free(sv->vector[i]);
    }

    free(sv);


}



void PushBackString2(struct VectorString** sv, char* new_str){


    int org_vec_size = (*sv)->size;

    int new_str_len = strlen(new_str);

    int new_vec_size = org_vec_size + 1;

    struct VectorString* new_vec = (struct VectorString*)malloc(sizeof(struct VectorString));

    new_vec->vector = (char**)malloc(new_vec_size * sizeof(char*));

    for(int i = 0 ; i < org_vec_size; i++){

        int line_strlen = strlen((*sv)->vector[i]) + 1;

        new_vec->vector[i] = (char*)malloc(line_strlen * sizeof(char));

        memset(new_vec->vector[i], 0, line_strlen * sizeof(char));

        strcpy(new_vec->vector[i], (*sv)->vector[i]);

        free((*sv)->vector[i]);
    }

    if(org_vec_size > 0){

        free((*sv)->vector);
    }


    free(*sv);    

    int new_line_strlen = strlen(new_str) + 1;

    new_vec->vector[org_vec_size] = (char*)malloc(new_line_strlen*sizeof(char));

    memset(new_vec->vector[org_vec_size], 0 , new_line_strlen * sizeof(char));

    strcpy(new_vec->vector[org_vec_size], new_str);

    new_vec->size = new_vec_size;

    *sv = new_vec;
 
}