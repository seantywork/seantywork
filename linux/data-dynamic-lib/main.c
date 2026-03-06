#include <stdio.h>
#include <dlfcn.h>


int main(){

 
    void *handle = NULL;

    void (*supvar_inc)(int);

    int (*supvar_get)();

    handle = dlopen ("./libsuperdym.so", RTLD_LAZY);

    if (handle == NULL){

        printf("failed to get handle\n");

        return -1;

    }

    supvar_inc = dlsym(handle, "super_var_increase");


    supvar_get = dlsym(handle, "super_var_get");


    printf("loaded\n");

    int supvar_val = supvar_get();

    printf("initial supvar: %d\n", supvar_val);

    supvar_inc(5);

    supvar_val = supvar_get();

    printf("new supvar: %d\n", supvar_val);

    dlclose(handle);

    handle = NULL;

    printf("unloaded\n");

    handle = dlopen ("./libsuperdym.so", RTLD_LAZY);

    if (handle == NULL){

        printf("failed to get handle once more\n");

        return -1;

    }

    supvar_inc = dlsym(handle, "super_var_increase");


    supvar_get = dlsym(handle, "super_var_get");

    printf("reloaded\n");

    supvar_val = supvar_get();

    printf("finally: %d\n", supvar_val);

    dlclose(handle);


    return 0;
}