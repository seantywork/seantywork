#include "h2.h"

int main(int argc, char **argv){
    
    int result = 0;
    if(argc != 2){
        printf("./bin [c|s]\n");
        return -1;
    }
    if(argv[1][0] == 'c'){
        result = client_run(H2_URL, H2_CA_CERT, H2_CLIENT_CERT, H2_CLIENT_KEY);
    } else if(argv[1][0] == 's') {
        result = server_run(H2_PORT, H2_CA_CERT, H2_SERVER_CERT, H2_SERVER_KEY);
    } else {
        printf("./bin [c|s]\n");
        return -1;
    }
    printf("result: %d\n", result);
    return result;
}