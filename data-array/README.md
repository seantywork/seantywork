# array

- [code](https://github.com/seantywork/seantywork/tree/main/data-array)

In a C program, array is one of the most common type of data container \
that can hold data in a contiguous (virtually, in a user space in this case) and same-sized memory spaces.

Below is the conceptual shape of a usual array.

```shell

0________1________2_________
+--------+--------+--------+
|        |        |        | 
| data1  | data2  | data3  |
|        |        |        |
+--------+--------+--------+
|___  total length: 3  ____|

```

You can google everything that you can ever come up with about how to play with array.\
Here, in this directory, I'm simply documenting what can happen to array when we pass the variable \
into a function and the case where we SHOULDN'T try to modify it.

In the code, there are three variables defined.

```c

    char arrforarr[MAX_CHAR_ARR_LEN] = {0};
    char arrforptr[MAX_CHAR_ARR_LEN] = {0};
    char *arrnotmutable = "original array not mutable";
```

I'm going to try to modify all three and see what happens. \
First, this is the function that will modify the variable `arrforarr`.

```c
void receive_char_arr(char arg[MAX_CHAR_ARR_LEN]){
    strcpy(arg, "modified array 1");
}
```
Next, is the function that will modify the variable `arrforptr`.

```c
void receive_char_ptr(char* arg){
    strcpy(arg, "modified array 2");
}
```

Finally, this will try to modify the variable `arrnotmutable`.

```c
void receive_char_ptr_print(char* arg){
    printf("before: %s\n", arg);
    strcpy(arg, "modified array 3");
    printf("after: %s\n", arg);
}
```

Let's compile and see what happens.

```shell
$ make
gcc -g -Wall -I. -o array.out main.c 

$ ./array.out 
starting arr: original array 1        # <--- original message
starting ptr: original array 2        # <--- original message
ending arr: modified array 1          # <----+
ending ptr: modified array 2          # <----- both are modified    
starting: original array not mutable  
before: original array not mutable    
Segmentation fault                    # <----- the third one cannot be modified

```

If we have GDB run it, we can see that precisely `strcpy` on\
the immutable region is the cause of this fault.

```shell
Program received signal SIGSEGV, Segmentation fault.
0x00000000004011bc in receive_char_ptr_print (arg=0x40201b "original array not mutable") at main.c:17
17          strcpy(arg, "modified array 3");
```