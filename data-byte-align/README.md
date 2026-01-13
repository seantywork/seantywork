# byte-align

- [code](https://github.com/seantywork/seantywork/tree/main/data-byte-align)

Byte-alignment means, in C program, that there could be \
meaningful gains (both in terms of performance and memory) for the programmers \
who give a good care when defining a struct as they write codes.

Let's first see how it can be utilized to write a memory-efficient \
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


```shell
$ getconf LEVEL1_DCACHE_LINESIZE
64

```



There is a thing called [cpu cache](https://en.wikipedia.org/wiki/CPU_cache). \
It doesn't matter for many programmers for the most time until it **DOES** matter eventually.
