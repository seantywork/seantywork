#include "random.h"





unsigned char* gen_random_bytestream (size_t num_bytes){
  
  unsigned char *stream = malloc (num_bytes);

  size_t i;

  for (i = 0; i < num_bytes; i++){

    stream[i] = rand();
  
  }

  return stream;
}

unsigned char* bin2hex(int arrlen, unsigned char* bytearray){

    unsigned char* hexarray;

    int hexlen = 2;

    int outstrlen = hexlen * arrlen + 1;

    hexarray = (char*)malloc(outstrlen * sizeof(char));

    memset(hexarray, 0, outstrlen * sizeof(char));

    unsigned char* ptr = hexarray;

    for(int i = 0 ; i < arrlen; i++){

        sprintf(ptr + 2 * i, "%02X", bytearray[i]);

        printf("%d: %c%c ", i, ptr[2 * i], ptr[2 * i + 1]);
    }

    printf("\n");

    return hexarray;
}
