#include "c_array.h"



void ArrAsArgInterface(){


    char arrforarr[MAX_CHAR_ARR_LEN] = {0};


    char arrforptr[MAX_CHAR_ARR_LEN] = {0};


    strcpy(arrforarr, "this is arr for arr");

    strcpy(arrforptr, "this is arr for ptrh");


    printf("starting arr: %s\n", arrforarr);

    printf("starting ptr: %s\n", arrforptr);


    ReceiveCharArr(arrforarr);


    ReceiveCharPtr(arrforptr);


    printf("ending arr: %s\n", arrforarr);

    printf("ending ptr: %s\n", arrforptr);


    
}