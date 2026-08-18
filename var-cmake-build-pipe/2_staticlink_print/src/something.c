
#include "something.h"

char name[15] = {0};


void init_something(char* in_name){

	strcpy(name, in_name);

}


void speak_something(){


	printf("the name of something is : %s\n", name);

}

