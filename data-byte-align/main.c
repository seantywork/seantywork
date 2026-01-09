#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>



typedef struct unaligned_tuple_struct {
	
	uint8_t proto;
	uint32_t saddr;
	uint32_t daddr;
	uint16_t sport;
	uint16_t dport;
	uint8_t policy;
	uint8_t rsvd[2];

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
	uint8_t rsvd[2];

} packed_tuple_struct;


int main(){


    printf("expect: 16\n");

	int data_size = sizeof(unaligned_tuple_struct);


	printf("unaligned size: %d\n", data_size);

    data_size = sizeof(aligned_tuple_struct);


	printf("aligned size: %d\n", data_size);

    data_size = sizeof(packed_tuple_struct);


	printf("packed size: %d\n", data_size);


	return 0;

}
