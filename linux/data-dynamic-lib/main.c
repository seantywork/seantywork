#include <stdio.h>
#include <dlfcn.h>
#include "super_dym.h"


int main(){
    void *handle = NULL;
    SUPER_DYM_FN_super_var_increase setter = NULL;
    SUPER_DYM_FN_super_var_get getter = NULL;
    handle = dlopen ("./libsuperdym.so", RTLD_LAZY);
    if (handle == NULL){
        printf("failed to get handle\n");
        return -1;
    }
    setter = dlsym(handle, SUPER_DYM_SYM_super_var_increase);
    getter = dlsym(handle, SUPER_DYM_SYM_super_var_get);
    printf("loaded\n");
    int supvar_val = getter();
    printf("initial supvar: %d\n", supvar_val);
    setter(5);
    supvar_val = getter();
    printf("new supvar: %d\n", supvar_val);
    dlclose(handle);
    handle = NULL;
    printf("unloaded\n");

    return 0;
}