#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_CHAR_ARR_LEN 1024

void receive_char_arr(char arg[MAX_CHAR_ARR_LEN]){
    strcpy(arg, "modified array 1");
}

void receive_char_ptr(char* arg){
    strcpy(arg, "modified array 2");
}

void receive_char_ptr_print(char* arg){
    printf("before: %s\n", arg);
    strcpy(arg, "modified array 3");
    printf("after: %s\n", arg);
}

int main (){

    char arrforarr[MAX_CHAR_ARR_LEN] = {0};
    char arrforptr[MAX_CHAR_ARR_LEN] = {0};
    char *arrnotmutable = "original array not mutable";

    strcpy(arrforarr, "original array 1");
    strcpy(arrforptr, "original array 2");

    printf("starting arr: %s\n", arrforarr);
    printf("starting ptr: %s\n", arrforptr);

    receive_char_arr(arrforarr);
    receive_char_ptr(arrforptr);

    printf("ending arr: %s\n", arrforarr);
    printf("ending ptr: %s\n", arrforptr);

    printf("starting: %s\n", arrnotmutable);
    receive_char_ptr_print(arrnotmutable);
    printf("ending: %s\n", arrnotmutable);

    return 0;
}