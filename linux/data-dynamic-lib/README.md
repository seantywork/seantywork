# dynamic-lib 

- [code](https://github.com/seantywork/seantywork/tree/main/linux/data-dynamic-lib)

Here, I'm demonstrating how to dynamically load and unload shared library during runtime.

Typically, when we run a program on linux machine, we don't usually have to worry about \
locating exact target shared library file to load because the linker handles it as a part \
of spawning a process (assuming that the location of the shared file \
is correctly provided at the compile time).

However, it's entirely possible, on Linux, to load the shared library \
**during runtime** and call functions and variable(pointer) from it.

We could do it by linking `dl` library when compiling.




