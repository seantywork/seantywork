#include <stdio.h>
#include <stdlib.h>


int _super_var;


int super_var_init(){
    _super_var = 0;
    return 0;
}

void super_var_increase(int by){
    _super_var += by;
}

int super_var_get(){
    return _super_var;
} 

void super_var_exit(){
    _super_var = 0;
}