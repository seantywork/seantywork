#ifndef _RANDOM_H_
#define _RANCOM_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>



unsigned char* gen_random_bytestream (size_t num_bytes);


unsigned char* bin2hex(int arrlen, unsigned char* bytearray);



#endif