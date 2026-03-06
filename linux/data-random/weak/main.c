#include "random.h"



int main(){


    srand ((unsigned int) time (NULL));


    unsigned char* randbytes = gen_random_bytestream(32);

    unsigned char* hex_str = bin2hex(32, randbytes);


    printf("%s\n", hex_str);

    free(randbytes);

    free(hex_str);


    return 0;
}