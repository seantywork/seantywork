#include "h2.h"

int main(){
    
    int result = 0;
    result = server_run(H2_PORT, H2_CA_CERT, H2_SERVER_CERT, H2_SERVER_KEY);
    printf("result: %d\n", result);
    return result;
}