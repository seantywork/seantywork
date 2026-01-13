#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <time.h>

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

#ifndef ALIGNIT
typedef struct align_or_not {
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

uint64_t lapse_sum_one = 0;
uint64_t lapse_sum_two = 0;

align_or_not* round_arr = NULL;
int spinlock = 0;

static inline bool atomic_compare_exchange(int* ptr, int compare, int exchange) {
    return __atomic_compare_exchange_n(ptr, &compare, exchange,
            0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
}
static inline void atomic_store(int* ptr, int value) {
    __atomic_store_n(ptr, value, __ATOMIC_SEQ_CST);
}

void spinlock_lock(int* locker) {
    while (!atomic_compare_exchange(locker, 0, 1)) {
    }
}

void spinlock_unlock(int* locker) {
    atomic_store(locker, 0);
}

void* thread_one(void* varg){
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
	uint16_t num = 0;
	uint64_t lapsed_ns = 0;
	for(int i = 0 ; i < ROUND; i++){
		struct timespec THEN;
		struct timespec NOW;
		num  = (uint16_t)i;
		spinlock_lock(&spinlock);
		clock_gettime(CLOCK_MONOTONIC_RAW, &THEN);
		for(int j = 0; j < ROUND_LENGTH; j++){
			round_arr[j].number1 += num; 
			round_arr[j].number2 += num; 
			round_arr[j].number3 += num; 
		}
		clock_gettime(CLOCK_MONOTONIC_RAW, &NOW);
		spinlock_unlock(&spinlock);
		lapsed_ns = ((NOW.tv_sec - THEN.tv_sec) * 1000000000 + (NOW.tv_nsec - THEN.tv_nsec));
		lapse_sum_one += lapsed_ns;
	}
	pthread_exit(NULL);
}

void* thread_two(void* varg){
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(1, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
	uint16_t num = 0;
	uint64_t lapsed_ns = 0;
	for(int i = 0 ; i < ROUND; i++){
		struct timespec THEN;
		struct timespec NOW;
		num  = (uint16_t)i;
		spinlock_lock(&spinlock);
		clock_gettime(CLOCK_MONOTONIC_RAW, &THEN);
		for(int j = 0; j < ROUND_LENGTH; j++){
			round_arr[j].number1 -= num; 
			round_arr[j].number2 -= num; 
			round_arr[j].number3 -= num; 
		}
		clock_gettime(CLOCK_MONOTONIC_RAW, &NOW);
		spinlock_unlock(&spinlock);
		lapsed_ns = ((NOW.tv_sec - THEN.tv_sec) * 1000000000 + (NOW.tv_nsec - THEN.tv_nsec));
		lapse_sum_two += lapsed_ns;
	}
	pthread_exit(NULL);
}

int main(){

	pthread_t t1;
	pthread_t t2;

    printf("expect: 16\n");
	int data_size = sizeof(unaligned_tuple_struct);
	printf("unaligned size: %d\n", data_size);
    data_size = sizeof(aligned_tuple_struct);
	printf("aligned size: %d\n", data_size);
    data_size = sizeof(packed_tuple_struct);
	printf("packed size: %d\n", data_size);

	printf("PERF TEST START\n");
#ifndef ALIGNIT
	printf("...with unaligned %d-byte struct\n", sizeof(align_or_not));
#else 
	printf("...with aligned %d-byte struct\n", sizeof(align_or_not));
#endif
	round_arr = (align_or_not*)calloc(ROUND_LENGTH, sizeof(align_or_not));

	printf("running perf test...\n");
	pthread_create(&t1, NULL, thread_one, NULL);
	pthread_create(&t2, NULL, thread_two, NULL);
	pthread_join(t1, NULL);
	pthread_join(t2, NULL);
	printf("completed\n");

	for(int i = 0; i < ROUND_LENGTH; i++){
		if(round_arr[i].number1 != 0){
			printf("failed 1 at: %d: %u\n", i, round_arr[i].number1);
			goto out;
		}
		if(round_arr[i].number2 != 0){
			printf("failed 2 at: %d: %u\n", i, round_arr[i].number2);
			goto out;
		}
		if(round_arr[i].number3 != 0){
			printf("failed 3 at: %d: %u\n", i, round_arr[i].number3);
			goto out;
		}
	}

	uint64_t avgone = lapse_sum_one / ROUND;
	uint64_t avgtwo = lapse_sum_two / ROUND;
    printf("took %llu ns\n", (avgone + avgtwo) / 2);
out:
	free(round_arr);
	return 0;

}
