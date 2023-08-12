#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
 
int main(){
 
    printf("make it overflow:\n");

    int var;
    int check = 0x04030201;
    char buf[10];

    fgets(buf,15,stdin);

    

    if ((check != 0x04030201) && (check != 0xdeadbeef)){
        printf ("\naffecting buffer...\n");
    }

    if (check == 0xdeadbeef) {
        printf("success\n");
        printf("[check] %p\n", check);
    } else {
        printf("failure\n");
        printf("[check] %p\n", check);
    }
    return 0;
}


