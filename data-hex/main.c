#include "hex.h"


int main(){


    char* test = "blahblahblah";

    int test_len = strlen(test);

    unsigned char* hex = bin2hex(test_len, (unsigned char*)test);


    printf("HEX: %s\n", hex);


    unsigned char* bin = hex2bin(hex);

    printf("BIN: %s\n", bin);


    free(hex);
    free(bin);

    return 0;



}