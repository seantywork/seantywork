# byte-align

- [code](https://github.com/seantywork/seantywork/tree/main/data-byte-align)

Byte-alignment means, in C program, that there could be \
meaningful gains (both in terms of performance and memory) for the programmers \
who give a good care when defining a struct as they write codes.

Before we start looking at the code, do try out the command below and find out \
the exact L1 cache line size.

```shell
$ getconf LEVEL1_DCACHE_LINESIZE
64

```

For me, it is 64. Keep this number in mind as everything happening from now on will \
depend on that number.

Let's first see how byte-alignment can be utilized to write a memory-efficient \
program. Look at the three types of struct below.

```c
typedef struct unaligned_tuple_struct {
	
	uint8_t proto;
	uint32_t saddr;
	uint32_t daddr;
	uint16_t sport;
	uint16_t dport;
	uint8_t policy;

} unaligned_tuple_struct;

typedef struct aligned_tuple_struct {
	
	uint32_t saddr;
	uint32_t daddr;
	uint16_t sport;
	uint16_t dport;
    uint8_t proto;
	uint8_t policy;
	uint8_t rsvd[2];

} aligned_tuple_struct;

typedef struct __attribute__((packed)) packed_tuple_struct {

	uint8_t proto;
	uint32_t saddr;
	uint32_t daddr;
	uint16_t sport;
	uint16_t dport;
	uint8_t policy;

} packed_tuple_struct;
```

As we can see, the first one (`unaligned_tuple_struct`) has its fields in a willy-nilly order. \
However, without further consideration, it just seems okay and our program looks like it's \
going to have a 14-byte struct.

In fact, it isn't.

If we compile the program and run it, given the `getconf` command returned the same output as mine, \
the below output is what we're likely to see instead.

```shell
$ make
gcc -g -o test.out main.c -lpthread
$ ./test.out 
expect: 14
unaligned size: 20
aligned size: 16
packed size: 14
PERF TEST START
...with unaligned 12-byte struct
running perf test...
^C   # <--- hit keyboard interrupt, explained later
```
What's happening exactly? Even if we define struct to be 14-byte, the compiler adds `padding` to that \
struct if it's not in an aligned format. As we can see, the `aligned_tuple_struct` is exactly the size \
we want it to be because the compiler is happy with the order of its fields and overall size which is \
devisible by `64`. To disable this behavior, we can specify `__attribute__((packed))` to have the struct \
sized exactly as we defined it.

However, here is one more thing. As I mentioned already at the start, byte-alignment affects memory **AND** performance. \
Even if we marked the struct with `__attribute__((packed))` and have a nice day with smaller struct, \
the problem of slower program lingers on as the fundamental cache line problem is unresolved.

If we run the program again, and don't hit keyboard interrupt, we'll see that how much time the program took to \
complete `ROUND` number of write actions on one struct array with `ROUND_LENGTH` elements from two competing threads.

You can find out and even customize the setting from the code. Here's the snippet.

```c

#ifndef ALIGNIT
typedef struct __attribute__((packed)) align_or_not {
	uint32_t number1;
	uint16_t number2;
	uint32_t number3;
} align_or_not;
#else 
typedef struct align_or_not {
	uint32_t number1;
	uint32_t number3;
	uint16_t number2;
	uint8_t rsvd[4];
} align_or_not;
#endif



#define ROUND 1000000
#define ROUND_LENGTH 2048

align_or_not* round_arr = NULL;
int spinlock = 0;
```
Basically, what we've just run was the performance of the unaligned version.

```shell
$ ./test.out 
expect: 14
unaligned size: 20
aligned size: 16
packed size: 14
PERF TEST START
...with unaligned 10-byte struct
running perf test...
completed
took 9035 ns  # <- calculated per round, then averaged over all rounds
```

Now with the recipe specified below, we can compile and run aligned version.

```shell
$ make alignit 
gcc -g -DALIGNIT -o test.out main.c -lpthread
$ ./test.out 
expect: 14
unaligned size: 20
aligned size: 16
packed size: 14
PERF TEST START
...with aligned 16-byte struct
running perf test...
completed
took 6934 ns  # <- calculated per round, then averaged over all rounds
```
Even if the struct itself is smaller in unaligned version, the overall performance was lagging behind \
that of the aligned version.