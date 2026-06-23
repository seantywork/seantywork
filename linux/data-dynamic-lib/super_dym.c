#include <stdio.h>
#include <stdlib.h>


int super_var;


int super_var_init(){
    super_var = 0;
    return 0;
}

void super_var_increase(int by){
    super_var += by;
}

int super_var_get(){
    return super_var;
} 

void super_var_exit(){
    super_var = 0;
}