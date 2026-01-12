# struct

- [code](https://github.com/seantywork/seantywork/tree/main/data-struct)


C struct is a data container that can hold different types of data within it.

An example struct could look like something below.

```shell

+----------------+
|  feature_type  |  uint8_t
+----------------+
|  enabled       |  uint8_t
+----------------+
|  feature_id    |  uint16_t
|                |
+----------------+
|  updated_ts    |  uint32_t
|                |
|                |
|                |
+----------------+

```

As we can see, the arbitrary container can hold four (or whatever number we may) \
differently-sized data types within contiguous memory layout.

There are more than plenty of detailed resources on C struct out there, so what I'm doing \
today is to simply document some useful-to-know facts about it.

See below struct.

```c
#define MAX_NAME_LEN sizeof(uint64_t)
#define MAX_MEMBER_ARR_LEN 1024
#define MAX_CHAR_ARR_LEN 1024
#define MAX_ROW_NUM 128

struct arr_one{
    union {
        char name[MAX_NAME_LEN];
        uint64_t id;
    };
    char comment[MAX_MEMBER_ARR_LEN];
};

struct ptr_one{
    union {
        char name[MAX_NAME_LEN];
        uint64_t id;
    };
    char* comment;
};
```
I made those two up in the code so that I can demonstrate `union` keyword and \
an important (I think) aspect of C struct copying.

First, `union` keyword can be utilized to efficiently cast between multiple types. \
Meaning that, we can do something like a below using `union`

```shell
+----------------+                 
|  feature_type  |  uint8_t          
+----------------+                  
|  enabled       |  uint8_t          
+----------------+              +----------------+      +----------------+
|  id_kind       |  union   --> |  id_kind       |  --> |   feature_id   |  
|  feature_id    | (2-byte)     +----------------+      |   uint16_t     |
+----------------+                  uint8_t             +----------------+   
|  updated_ts    |  uint32_t
|                |
|                |
|                |
+----------------+

```

`union` field takes up the most memory required by its member fields\
(which is 2-byte`feature_id`), and it's allowed to convert freely between \
`id_kind` and `feature_id`. 

If we're using a plain field `feature_id` alone, we have to convert explicitly \
everytime we're performing an operation on that area of memory.

In the code, its convenience is demonstrated by the below lines.

```c
    strncpy(src_a.name,"abcdefg", MAX_NAME_LEN);
    strncpy(src_p.name,"ijklmno", MAX_NAME_LEN);
    src_p.id = src_a.id;

```
Assigning different names to two different struct variables using `strncpy`, \
then overwriting one with the other with simple operand.

Another important thing to remember is that we can copy one struct from the \
other using a simple assignment operation, but the result might differ \
depending on how we define the base struct type.

If we define a staticly-size array within a struct, the whole value will be\
copied to the destination variable. If we define it as a simple pointer, \
then only the address of that array will be passed on, hence affecting the \
original value when we pull any operation on that field.

Here are the two functions to test out how struct copying works.

```c
void receive_struct_with_arr(struct arr_one a){
    strcpy(a.comment, "modified array 1");
}

void receive_struct_with_ptr(struct ptr_one p){
    strcpy(p.comment, "modified array 2");
}
```

This can be seen by compiling and running the program.

```shell

$ make
gcc -g -Wall -I. -o struct.out main.c 
$ ./struct.out 
start: name for arr: abcdefg
start: comment for arr: original array 1
start: name for ptr: abcdefg              # < this is the result of `union` op
start: comment for ptr: original array 2
end: name for arr: abcdefg
end: comment for arr: original array 1    # < passed by value, not modified
end: name for ptr: abcdefg
end: comment for ptr: modified array 2    # < passed by reference, so this happens

```