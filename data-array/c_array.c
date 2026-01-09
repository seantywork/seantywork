#include "c_array.h"


void ReceiveCharArr(char arg[MAX_CHAR_ARR_LEN]){


    printf("received from arr: %s\n", arg);



    strcpy(arg, "arr original value modifed");



    printf("changed from arr: %s\n", arg);




}

void ReceiveCharPtr(char* arg){


    printf("received from ptr: %s\n", arg);


    strcpy(arg, "ptr original valued modified");


    printf("change from ptr: %s\n", arg);


}