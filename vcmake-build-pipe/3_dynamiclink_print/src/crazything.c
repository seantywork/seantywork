#include "crazything.h"

char status[15] = {0};


void init_crazything(char* in_status){

	strcpy(status, in_status);


}

void yell_crazything(){


	printf("...AND I'M SUFFERING FROM %s\n", status);
}




