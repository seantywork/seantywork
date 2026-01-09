#include "c_struct.h"


void StructCopyThreadInterface(){


    int done = 0;

    pthread_t tid1;

    pthread_t tid2;

    char comment_arr[MAX_MEMBER_ARR_LEN] = {0};

    strcpy(comment_arr, "comment for arr");

    char comment_ptr[MAX_MEMBER_ARR_LEN] = {0};

    strcpy(comment_ptr, "comment for ptr");

    /*
        comment pointer not transferred
    struct StructWithArr sarr = {
        .name = 0,
        .comment = comment_arr
    };
    */

    struct StructWithArr sarr;

    sarr.name = 0;
    
    strcpy(sarr.comment, comment_arr);

    struct StructWithPtr sptr = {
        .name = 1,
        .comment = comment_ptr
    };

    printf("start: comment for arr: %s\n", sarr.comment);

    printf("start: comment for ptr: %s\n", sptr.comment);

    pthread_create(&tid1, NULL, StructCopyThreadForSarr, (void*)&sarr);

    pthread_create(&tid2, NULL, StructCopyThreadForSptr, (void*)&sptr);


    while(done == 0){

        printf("hit 1 to stop: ");

        scanf("%d", &done);

    }


    printf("end: comment for arr: %s\n", sarr.comment);

    printf("end: comment for ptr: %s\n", comment_ptr);

}




void Print2dBufferFromStruct(char* source){

    int row_num = 0;

    char* delim = "\n";

    char* s_tmp = source;

    while(s_tmp != NULL)                                                                                                    
    {                                                                                                                       
        s_tmp = strchr(s_tmp, '\n');                                                                                                           
        if( s_tmp ) {
            s_tmp++;
            row_num++;
        }                                                                                                
    }

    printf("row_num: %d\n", row_num);


    struct StructWith2dArr s2darr_source;

    struct StructWith2dArr s2darr_dest;


    char* ptk = strtok(source, delim);

    int row = 0;

    while(ptk != NULL){

        int line_len= 0;

        line_len = strlen(ptk);

        s2darr_source.td_buff[row] = (char*)malloc(line_len * sizeof(char) + 1);

        memset(s2darr_source.td_buff[row], 0 , line_len + 1);

        strcpy(s2darr_source.td_buff[row], ptk);

        row++;

        ptk = strtok(NULL, delim);
                
    }

    printf("td_buff\n");

    s2darr_source.dd_buff = (char**)malloc(row * sizeof(char*));

    for(int i = 0; i < row; i ++){

        int line_len = strlen(s2darr_source.td_buff[i]);

        s2darr_source.dd_buff[i] = (char*)malloc(line_len * sizeof(char) + 1);

        memset(s2darr_source.dd_buff[i], 0 , line_len + 1);

        strcpy(s2darr_source.dd_buff[i], s2darr_source.td_buff[i]);

    }


    printf("row num: %d, row: %d\n", row_num, row);

    int first_line_len = strlen(s2darr_source.td_buff[0]);

    s2darr_source.first_line_ptr = (char*)malloc(first_line_len * sizeof(char) + 1 );

    memset(s2darr_source.first_line_ptr, 0, first_line_len + 1);

    strcpy(s2darr_source.first_line_ptr, s2darr_source.td_buff[0]);

    strcpy(s2darr_source.first_line_arr, s2darr_source.td_buff[0]);

    s2darr_dest = s2darr_source;

    strcpy(s2darr_dest.dd_buff[0],"OVERWRITTEN_DD");

    strcpy(s2darr_dest.td_buff[0],"OVERWRITTEN_TD");

    strcpy(s2darr_dest.first_line_ptr,"OVERWRITTEN_PTR");

    strcpy(s2darr_dest.first_line_arr,"OVERWRITTEN_ARR");

    for(int i = 0; i < row; i ++){

        printf("[ SOURCE DD LINE %d ]: %s\n",i, s2darr_source.dd_buff[i]);
        printf("[ DEST   DD LINE %d ]: %s\n",i, s2darr_dest.dd_buff[i]);
        printf("[ SOURCE TD LINE %d ]: %s\n",i, s2darr_source.td_buff[i]);
        printf("[ DEST   TD LINE %d ]: %s\n",i, s2darr_dest.td_buff[i]);

    }
    printf("[ SOURCE PTR LINE ]: %s\n", s2darr_source.first_line_ptr);
    printf("[ DEST   PTR LINE ]: %s\n", s2darr_dest.first_line_ptr);
    printf("[ SOURCE ARR LINE ]: %s\n", s2darr_source.first_line_arr);
    printf("[ DEST   ARR LINE ]: %s\n", s2darr_dest.first_line_arr);


    printf("[ EOF ]\n");

    for(int i = 0; i < row; i ++){

        free(s2darr_source.td_buff[i]);
        free(s2darr_source.dd_buff[i]);

    }

    free(s2darr_source.dd_buff);

    free(s2darr_source.first_line_ptr);

}

