#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>

#define TESTCASE 100000
#define BUFFSIZE 1024

typedef struct DL_DATA DL_DATA;


struct DL_DATA {
	void* data;
	uint32_t datalen;
	DL_DATA* prev;
	DL_DATA* next;
};

typedef struct DL {
	uint32_t limit;
	uint32_t len;
	pthread_mutex_t lock;
	pthread_cond_t sig;
	DL_DATA* qh;
	DL_DATA* qt;
} DL;

typedef struct testdata {
    uint32_t top;
    uint32_t bottom;
} testdata;

struct timespec THEN;
struct timespec NOW;

DL* make_dl(uint32_t limit){
	DL* dl = (DL*)malloc(sizeof(DL));
	memset(dl, 0, sizeof(DL));
	pthread_mutex_init(&dl->lock, NULL);
	pthread_cond_init(&dl->sig, NULL);
	dl->limit = limit;
	return dl;
}

void clear_dl(DL* dl){
	pthread_mutex_lock(&dl->lock);
	DL_DATA* data = NULL;
	for(;;){
		if(dl->qh == NULL){
			break;
		}
		data = dl->qh->next;
		free(dl->qh);
		dl->qh = data;
	}
	pthread_mutex_unlock(&dl->lock);
	free(dl);
}

int enq(DL* dl, void* data, uint32_t datalen){
	int idx = 0;
	for(;;){
		pthread_mutex_lock(&dl->lock);
		if(dl->limit == dl->len){
			pthread_cond_wait(&dl->sig, &dl->lock);
		}
		DL_DATA* newd = (DL_DATA*)malloc(sizeof(DL_DATA));
		memset(newd, 0, sizeof(DL_DATA));
		newd->data = malloc(datalen);
		newd->datalen = datalen;
		memcpy(newd->data, data, newd->datalen);
		newd->prev = NULL;
		newd->next = dl->qh;
		if(dl->len == 0){
			dl->qt = newd;
			pthread_cond_broadcast(&dl->sig);
		}else {
			dl->qh->prev = newd;
		}
		dl->qh = newd;
		dl->len += 1;
		idx = dl->len;
		pthread_mutex_unlock(&dl->lock);
		break;
	}
	return idx;
}

int deq(DL* dl, void* data, uint32_t datalen){
	int idx = 0;
	for(;;){
		pthread_mutex_lock(&dl->lock);
		if(dl->len == 0){
			pthread_cond_wait(&dl->sig, &dl->lock);
		}
		DL_DATA* d = dl->qt;
		memcpy(data, d->data, datalen);
		dl->qt = d->prev;
		free(d->data);
		free(d);
		if(dl->len == 1){
			dl->qh = NULL;
			dl->qt = NULL;
		}else {
			dl->qt->next = NULL;
			if(dl->len == dl->limit){
				pthread_cond_broadcast(&dl->sig);
			}
		}
		dl->len -= 1;
		idx = dl->len;
		pthread_mutex_unlock(&dl->lock);
		break;
	}
	return idx;
}


void* do_enqueue(void* varg){
    testdata td;
    DL* q = (DL*)varg;
    clock_gettime(CLOCK_MONOTONIC_RAW, &THEN);
    for(int i = 0 ; i < TESTCASE; i++){
        td.top = i + 1;
        td.bottom =  i -1;
        enq(q, &td, sizeof(testdata));
    }
    pthread_exit(NULL);
}

int do_dequeue(DL* q){
    int counter = 0;
    testdata td;
    for(;counter < TESTCASE;){
        deq(q, &td, sizeof(testdata));
        if(td.top != (uint32_t)(counter + 1)){
            return -1;
        }
        if(td.bottom != (uint32_t)(counter - 1)){
            return -2;
        }
        counter += 1;
    }
    clock_gettime(CLOCK_MONOTONIC_RAW, &NOW);
    return 0;
}

int main(){


    int lapsed_ms = 0;
    int result = 0;
    pthread_t tid;
    DL* q = make_dl(BUFFSIZE);
    pthread_create(&tid, NULL, do_enqueue, (void *)q);
    if((result = do_dequeue(q)) < 0){
        printf("error: %d\n", result);
        goto exit;
    }
    lapsed_ms = ((NOW.tv_sec - THEN.tv_sec) * 1000 + (NOW.tv_nsec - THEN.tv_nsec) / 1000000);
    printf("%d-entry, sized %d-byte, took %dms\n", TESTCASE, sizeof(testdata), lapsed_ms);
exit:
    clear_dl(q);
    return 0;
}