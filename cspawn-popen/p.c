
#include <stdio.h>
#include <stdlib.h>


int main(int argc,char *argv[]){    
    FILE* file = popen("ls", "r");
    char buffer[100];
    fgets(buffer, 100, file);
    pclose(file);
    printf("buffer is :%s\n", buffer);
    return 0;
}