#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define MAX_MEMBER_ARR_LEN 1024
#define MAX_CHAR_ARR_LEN 1024
#define MAX_ROW_NUM 128

struct arr_one{
    int name;
    char comment[MAX_MEMBER_ARR_LEN];
};

struct ptr_one{
    int name;
    char* comment;
};

void receive_struct_with_arr(struct arr_one a){

    strcpy(a.comment, "modified array 1");
}

void receive_struct_with_ptr(struct ptr_one p){
    strcpy(p.comment, "modified array 2");
}

int main (){


    char comment_ptr[MAX_MEMBER_ARR_LEN] = {0};
    struct arr_one src_a;
    struct ptr_one src_p;


    memset(&src_a, 0, sizeof(struct arr_one));
    memset(&src_p, 0, sizeof(struct ptr_one));

    strcpy(src_a.comment, "original array 1");
    strcpy(comment_ptr, "original array 2");
    src_p.comment = comment_ptr;
    src_a.name = 1;
    src_p.name = 2;
    
    printf("start: name for arr: %d\n", src_a.name);
    printf("start: comment for arr: %s\n", src_a.comment);
    printf("start: name for ptr: %d\n", src_p.name);
    printf("start: comment for ptr: %s\n", src_p.comment);

    receive_struct_with_arr(src_a);
    receive_struct_with_ptr(src_p);

    printf("end: name for arr: %d\n", src_a.name);
    printf("end: comment for arr: %s\n", src_a.comment);
    printf("end: name for ptr: %d\n", src_p.name);
    printf("end: comment for ptr: %s\n", src_p.comment);
    return 0;
}