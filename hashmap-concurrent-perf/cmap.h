#ifndef _CMAP_PERF_H_ 
#define _CMAP_PERF_H_


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>

#define _BOGUS_KEY struct { \
    uint64_t index; \
}

#define BOGUS_KEY _BOGUS_KEY

typedef struct BOGUS_DATA BOGUS_DATA;

struct BOGUS_DATA {
    BOGUS_KEY;
    uint64_t value;
    uint64_t in_use;
    BOGUS_DATA* next;
};

typedef struct BOGUS_BUCKET{
    BOGUS_DATA* data;
    pthread_mutex_t lock;
} BOGUS_BUCKET;

typedef struct BOGUS_CMAP{
    BOGUS_BUCKET* buck;
    int buck_size;
} BOGUS_CMAP;



BOGUS_CMAP* cmap_alloc(int buck_size, int data_size);
int cmap_set(BOGUS_CMAP* cm, BOGUS_DATA* val);
int cmap_get(BOGUS_CMAP* cm, BOGUS_DATA* key, void* ret, void (*cb)(void* ret, void* data));
int cmap_del(BOGUS_CMAP* cm, BOGUS_DATA* key);
void cmap_free(BOGUS_CMAP* cm);



#endif