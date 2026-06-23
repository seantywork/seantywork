# dynamic-lib 

- [code](https://github.com/seantywork/seantywork/tree/main/linux/data-dynamic-lib)

Here, I'm demonstrating how to dynamically load and unload shared library during runtime.

Typically, when we run a program on linux machine, we don't usually have to worry about \
locating exact target shared library file to load because the linker handles it as a part \
of spawning a process (assuming that the location of the shared file \
is correctly provided at the compile time).

However, it's entirely possible, on Linux, to load the shared library \
**during runtime** and call functions and variables from it.

We could do it by linking `dl` library when compiling.

Below is the recipe of the Makefile for building linkable shared \
library and our target executable.

```Makefile
build: libsuperdym.so

	gcc -g -O2 -o test.out main.c -ldl

libsuperdym.so:
	gcc -Wall -g -O2 -c -fPIC -o super_dym.o super_dym.c
	gcc -g -O2 -shared -o libsuperdym.so super_dym.o

clean:
	rm -rf *.so *.out *.o

```
As you can see, our target executable is not linking `libsuperdym.so` \
at the compile time.

Looking at the code in `main.c`, we're able to find out when exactly \
during the runtime we're linking the shared library.

```c
    // every SUPER_DYM_XX is defined in
    // super_dym.h 
    // so that a user of the shared library 
    // can know what symbols are exported
 
    void *handle = NULL;
    SUPER_DYM_FN_super_var_init in = NULL;
    SUPER_DYM_FN_super_var_increase setter = NULL;
    SUPER_DYM_FN_super_var_get getter = NULL;
    SUPER_DYM_FN_super_var_exit out = NULL;
    SUPER_DYM_VAR_super_var* v = NULL;

    // here, link the shared library directly
    handle = dlopen ("./libsuperdym.so", RTLD_LAZY);
    if (handle == NULL){
        printf("failed to get handle\n");
        return -1;
    }
    // variable can be imported this way...
    void* _v = dlsym(handle, SUPER_DYM_SYM_super_var);
    v = (SUPER_DYM_VAR_super_var*)_v;

    // ... and functions like this below
    in = dlsym(handle, SUPER_DYM_SYM_super_var_init);
    setter = dlsym(handle, SUPER_DYM_SYM_super_var_increase);
    getter = dlsym(handle, SUPER_DYM_SYM_super_var_get);
    out = dlsym(handle, SUPER_DYM_SYM_super_var_exit);

```

Below are the exported functions and a variable from `libsuperdym.so`.

```c
int super_var;


int super_var_init(){
    super_var = 0;
    return 0;
}

void super_var_increase(int by){
    super_var += by;
}

int super_var_get(){
    return super_var;
} 

void super_var_exit(){
    super_var = 0;
}
```
The `test.out` binary will try to get/set the value of `super_var` in \
multiple ways.

Running the program, you will see the program works correctly.


```shell
$ make build 
gcc -Wall -g -O2 -c -fPIC -o super_dym.o super_dym.c
gcc -g -O2 -shared -o libsuperdym.so super_dym.o
gcc -g -O2 -o test.out main.c -ldl

$ ./test.out 
loaded
initial supvar: 0
var direct access: 0
new supvar: 5
var direct access: 5
unloaded
```

Thanks!
