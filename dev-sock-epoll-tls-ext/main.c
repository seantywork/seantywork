#include "h2.h"

int main(int argc, char **argv){
    
    int result = 0;
    if(argc < 2){
        printf("./bin [c|s]\n");
        return -1;
    }
    if(argv[1][0] == 'c'){
        if(argc != 6){
            printf("./bin c URL CA CERT KEY\n");
            return -1;
        }
        result = client_run(argv[2], argv[3],argv[4], argv[5]);
    } else if(argv[1][0] == 's') {
        if(argc != 6){
            printf("./bin s PORT CA CERT KEY\n");
            return -1;
        }
        result = server_run(argv[2], argv[3],argv[4], argv[5]);
    } else {
        printf("./bin [c|s]\n");
        return -1;
    }
    printf("result: %d\n", result);
    return result;
}