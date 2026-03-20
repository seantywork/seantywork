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

#define HASHSHA 0
#define HASHFNV 1
#define USE_DEF_MAP 1

#define _BOGUS_VAL struct { \
    uint64_t index; \
    uint64_t value; \
}

typedef struct bogus_data {
    _BOGUS_VAL;
} bogus_data;



#endif