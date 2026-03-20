#ifndef _CMAP_DEF_H
#define _CMAP_DEF_H

#include "cmap.h"



#if USE_DEF_MAP
#define DECL_MAP(__map_t, __data_t) \
typedef struct __map_t##_node __map_t##_node; \
struct __map_t##_node { \
    __data_t data; \
    uint8_t in_use; \
    __map_t##_node* next; \
}; \
typedef struct __map_t##_bucket{ \
    __map_t##_node* bucket; \
	pthread_mutex_t lock; \
} __map_t##_bucket; \
typedef struct __map_t{ \
    __map_t##_bucket* buckets; \
    uint64_t hashsize; \
    uint64_t (*hashfunc)(uint8_t* data, size_t size, uint64_t div); \
    uint8_t (*getok)(void* data, void* key); \
    uint8_t (*setok)(void* data, void* val); \
    uint8_t (*delok)(void* data); \
    uint64_t count; \
} __map_t; \
__map_t* __map_t##_create(int count, int depth, \
    uint64_t (*hashfunc)(uint8_t* data, size_t size, uint64_t div), \
    uint8_t (*getok)(void* data, void* key),\
    uint8_t (*setok)(void* data, void* val), \
    uint8_t (*delok)(void* data)); \
int __map_t##_set(__map_t* wmap, __data_t* val); \
int __map_t##_get(__map_t* wmap, __data_t* key, void* ret, void (*cb)(void* ret, void* data)); \
int __map_t##_del(__map_t* wmap, __data_t* key); \
void __map_t##_clear(__map_t* wmap); \

#define DEF_MAP(__map_t, __data_t, __key_t, __key_name) \
__map_t* __map_t##_create(int count, int depth, \
    uint64_t (*hashfunc)(uint8_t* data, size_t size, uint64_t div), \
    uint8_t (*getok)(void* data, void* key),\
    uint8_t (*setok)(void* data, void* val), \
    uint8_t (*delok)(void* data)){ \
    __map_t* wmap = (__map_t*)malloc(sizeof(__map_t)); \
    memset(wmap, 0, sizeof(__map_t)); \
    wmap->buckets = (__map_t##_bucket*)malloc(count * sizeof(__map_t##_bucket)); \
    wmap->count = (uint64_t)count; \
    wmap->hashsize = sizeof(__key_t); \
    wmap->hashfunc = hashfunc; \
    wmap->setok = setok; \
    wmap->getok = getok; \
    wmap->delok = delok; \
    for(int i = 0 ; i < count; i++){ \
        pthread_mutex_init(&wmap->buckets[i].lock, NULL); \
        wmap->buckets[i].bucket = NULL; \
        for(int j = 0 ; j < depth; j++){ \
            __map_t##_node* n = (__map_t##_node*)malloc(sizeof(__map_t##_node)); \
            memset(n, 0, sizeof(__map_t##_node)); \
            n->next = wmap->buckets[i].bucket; \
            wmap->buckets[i].bucket = n; \
        } \
    } \
    return wmap; \
} \
int __map_t##_set(__map_t* wmap, __data_t* val){ \
    int idx = -1; \
    __map_t##_node* data = NULL; \
    uint64_t hashkey = wmap->hashfunc((uint8_t*)&val->__key_name, wmap->hashsize, wmap->count); \
    pthread_mutex_lock(&wmap->buckets[hashkey].lock); \
    data = wmap->buckets[hashkey].bucket; \
    for(;;){ \
        if(data == NULL){ \
            data = (__map_t##_node*)malloc(sizeof(__map_t##_node)); \
            memset(data, 0, sizeof(__map_t##_node)); \
            if(wmap->setok(&data->data, val)){ \
                idx = hashkey; \
                data->in_use = 1; \
                data->next = wmap->buckets[hashkey].bucket; \
                wmap->buckets[hashkey].bucket = data; \
            } else { \
                free(data); \
            } \
            break; \
        } \
        if(data->in_use){ \
            data = data->next; \
            continue; \
        } \
        if(wmap->setok(&data->data, val)){ \
            idx = hashkey; \
            data->in_use = 1; \
            goto out; \
        } \
        data = data->next; \
    } \
out: \
    pthread_mutex_unlock(&wmap->buckets[hashkey].lock); \
    return idx; \
} \
int __map_t##_get(__map_t* wmap, __data_t* key, void* ret, void (*cb)(void* ret, void* data)){ \
    int idx = -1; \
    __map_t##_node* data = NULL; \
    uint64_t hashkey = wmap->hashfunc((uint8_t*)&key->__key_name, wmap->hashsize, wmap->count); \
    pthread_mutex_lock(&wmap->buckets[hashkey].lock); \
    data = wmap->buckets[hashkey].bucket; \
    for(;;){ \
        if(data == NULL){ \
            break; \
        } \
        if(data->in_use){ \
            if(wmap->getok(&data->data, key)){ \
                idx = hashkey; \
                goto out; \
            } \
        } \
        data = data->next; \
    } \
found: \
    if(ret != NULL && cb != NULL){ \
        cb(ret, &data->data); \
    } \
out: \
    pthread_mutex_unlock(&wmap->buckets[hashkey].lock); \
    return idx; \
} \
int __map_t##_del(__map_t* wmap, __data_t* key){ \
    int idx = -1; \
    __map_t##_node* data = NULL; \
    uint64_t hashkey = wmap->hashfunc((uint8_t*)&key->__key_name, wmap->hashsize, wmap->count); \
    pthread_mutex_lock(&wmap->buckets[hashkey].lock); \
    data = wmap->buckets[hashkey].bucket; \
    for(;;){ \
        if(data == NULL){ \
            break; \
        } \
        if(data->in_use){ \
            if(wmap->getok(&data->data, key)){ \
                if(wmap->delok(&data->data)){ \
                    data->in_use = 0; \
                    idx = hashkey; \
                    goto out; \
                } \
            } \
        } \
        data = data->next; \
    } \
out: \
    pthread_mutex_unlock(&wmap->buckets[hashkey].lock); \
    return idx; \
} \
void __map_t##_clear(__map_t* wmap){ \
    __map_t##_node* n = NULL; \
    for(int i = 0 ; i < wmap->count; i++){ \
        pthread_mutex_lock(&wmap->buckets[i].lock); \
        n = wmap->buckets[i].bucket; \
        for(;;){ \
            if(n == NULL){ \
                break; \
            } \
            wmap->buckets[i].bucket = n->next; \
            free(n); \
            n = wmap->buckets[i].bucket; \
        } \
        pthread_mutex_unlock(&wmap->buckets[i].lock); \
    } \
    free(wmap->buckets); \
    free(wmap); \
} 

#else 

typedef struct BOGUS_CMAP_node BOGUS_CMAP_node; 
struct BOGUS_CMAP_node { 
    bogus_data data; 
    uint8_t in_use; 
    BOGUS_CMAP_node* next; 
}; 
typedef struct BOGUS_CMAP_bucket{ 
    BOGUS_CMAP_node* bucket; 
	pthread_mutex_t lock; 
} BOGUS_CMAP_bucket; 
typedef struct BOGUS_CMAP{ 
    BOGUS_CMAP_bucket* buckets; 
    uint64_t hashsize; 
    uint64_t (*hashfunc)(uint8_t* data, size_t size, uint64_t div); 
    uint8_t (*getok)(void* data, void* key); 
    uint8_t (*setok)(void* data, void* val);
    uint8_t (*delok)(void* data); 
    uint64_t count; 
} BOGUS_CMAP; 
BOGUS_CMAP* BOGUS_CMAP_create(int count, int depth, 
    uint64_t (*hashfunc)(uint8_t* data, size_t size, uint64_t div), 
    uint8_t (*getok)(void* data, void* key),
    uint8_t (*setok)(void* data, void* val), 
    uint8_t (*delok)(void* data));
int BOGUS_CMAP_set(BOGUS_CMAP* wmap, bogus_data* val);
int BOGUS_CMAP_get(BOGUS_CMAP* wmap, bogus_data* key, void* ret, void (*cb)(void* ret, void* data));
int BOGUS_CMAP_del(BOGUS_CMAP* wmap, bogus_data* key);
void BOGUS_CMAP_clear(BOGUS_CMAP* wmap);

#endif

#if USE_DEF_MAP
DECL_MAP(BOGUS_CMAP, bogus_data)
#endif




#endif 