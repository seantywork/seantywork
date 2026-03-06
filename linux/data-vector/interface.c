#include "c_vector.h"

void VectorStringInterface(){

    char source[MAX_STREAM_LEN] = {0};

    FILE *fp = fopen("test.txt", "r");
    if (fp != NULL) {
        if (fseek(fp, 0L, SEEK_END) == 0) {
            
            long bufsize = ftell(fp);
            
            if (bufsize == -1) { 
                exit(EXIT_FAILURE);
            }

            printf("total buff len: %ld\n", bufsize);

            if (fseek(fp, 0L, SEEK_SET) != 0) { 
                exit(EXIT_FAILURE);
            }

            size_t read_len = fread(source, sizeof(char), bufsize, fp);
            if ( ferror( fp ) != 0 ) {
                fputs("error reading file", stderr);
            } else {
                source[read_len++] = '\0';
            }
        }
        fclose(fp);
    }


    PrintReducedVectorString(source);



}

void PrintReducedVectorString(char* source){

    struct VectorString vs;

    vs.size = 0;

    char* delim = "\n";  

    char* line_ptr;    

    while ((line_ptr = strsep(&source, delim)) != NULL) {  

        int status = VECTOR_PushBackString(vs.size, &vs.vector, line_ptr);

        if(status < -1){

            printf("error: push back\n");

            exit(-1);
        }

        vs.size += 1;

    }

    printf("=====BEFORE REDUCE=====\n");

    for(int i = 0 ; i < vs.size; i++){

        printf("[ %d ]: ",i);

        printf("%s\n",vs.vector[i]);

    }


    printf("=====BEFORE REDUCE=====\n");


    int status = VECTOR_EraseString(vs.size, &vs.vector, 17);

    if(status < 0){
        printf("error: reduce\n");
        exit(-2);
    }

    vs.size -= 1;

    printf("======AFTER REDUCE 17=====\n");

    for(int i = 0 ; i < vs.size; i++){

        printf("[ %d ]: ",i);

        printf("%s\n",vs.vector[i]);

    }


    printf("======AFTER REDUCE 17=====\n");

    status = VECTOR_EraseString(vs.size, &vs.vector, 19);

    if(status < 0){
        printf("error: reduce\n");
        exit(-2);
    }

    vs.size -= 1;

    printf("======AFTER REDUCE 19=====\n");

    for(int i = 0 ; i < vs.size; i++){

        printf("[ %d ]: ",i);

        printf("%s\n",vs.vector[i]);

    }


    printf("======AFTER REDUCE 19=====\n");


    for(int i = 0 ; i < vs.size; i++ ){

        free(vs.vector[i]);

    }

    free(vs.vector);

}

