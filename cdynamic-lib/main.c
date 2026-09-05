#include <stdio.h>
#include <dlfcn.h>
#include "super_dym.h"


int main(){
    void *handle = NULL;
    SUPER_DYM_FN_super_var_init in = NULL;
    SUPER_DYM_FN_super_var_increase setter = NULL;
    SUPER_DYM_FN_super_var_get getter = NULL;
    SUPER_DYM_FN_super_var_exit out = NULL;
    SUPER_DYM_VAR_super_var* v = NULL;

    handle = dlopen ("./libsuperdym.so", RTLD_LAZY);
    if (handle == NULL){
        printf("failed to get handle\n");
        return -1;
    }
    void* _v = dlsym(handle, SUPER_DYM_SYM_super_var);
    v = (SUPER_DYM_VAR_super_var*)_v;
    in = dlsym(handle, SUPER_DYM_SYM_super_var_init);
    setter = dlsym(handle, SUPER_DYM_SYM_super_var_increase);
    getter = dlsym(handle, SUPER_DYM_SYM_super_var_get);
    out = dlsym(handle, SUPER_DYM_SYM_super_var_exit);
    printf("loaded\n");
    int result = in();
    if(result < 0){
        printf("failed to init\n");
        return -1;
    }
    int val = getter();
    printf("initial supvar: %d\n", val);
    printf("var direct access: %d\n", *v);
    setter(5);
    val = getter();
    printf("new supvar: %d\n", val);
    printf("var direct access: %d\n", *v);
    out();
    dlclose(handle);
    handle = NULL;
    printf("unloaded\n");

    return 0;
}