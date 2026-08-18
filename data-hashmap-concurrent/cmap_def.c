#include "cmap_def.h"

#if USE_DEF_MAP
DEF_MAP(BOGUS_CMAP, bogus_data, uint64_t, index)
#else 

BOGUS_CMAP* BOGUS_CMAP_create(int count, int depth, 
    uint64_t (*hashfunc)(uint8_t* data, size_t size, uint64_t div), 
    uint8_t (*getok)(void* data, void* key),
    uint8_t (*setok)(void* data, void* val), 
    uint8_t (*delok)(void* data)){ 
    BOGUS_CMAP* wmap = (BOGUS_CMAP*)malloc(sizeof(BOGUS_CMAP));
    memset(wmap, 0, sizeof(BOGUS_CMAP)); 
    wmap->buckets = (BOGUS_CMAP_bucket*)malloc(count * sizeof(BOGUS_CMAP_bucket)); 
    wmap->count = (uint64_t)count; 
    wmap->hashsize = sizeof(__key_t); 
    wmap->hashfunc = hashfunc; 
    wmap->setok = setok; 
    wmap->getok = getok; 
    wmap->delok = delok; 
    for(int i = 0 ; i < count; i++){ 
        pthread_mutex_init(&wmap->buckets[i].lock, NULL); 
        wmap->buckets[i].bucket = NULL; 
        for(int j = 0 ; j < depth; j++){ 
            BOGUS_CMAP_node* n = (BOGUS_CMAP_node*)malloc(sizeof(BOGUS_CMAP_node)); 
            memset(n, 0, sizeof(BOGUS_CMAP_node)); 
            n->next = wmap->buckets[i].bucket; 
            wmap->buckets[i].bucket = n; 
        } 
    } 
    return wmap; 
} 
int BOGUS_CMAP_set(BOGUS_CMAP* wmap, bogus_data* val){ 
    int idx = -1; 
    BOGUS_CMAP_node* data = NULL; 
    uint64_t hashkey = wmap->hashfunc((uint8_t*)&val->key, wmap->hashsize, wmap->count); 
    pthread_mutex_lock(&wmap->buckets[hashkey].lock); 
    data = wmap->buckets[hashkey].bucket; 
    for(;;){ 
        if(data == NULL){ 
            data = (BOGUS_CMAP_node*)malloc(sizeof(BOGUS_CMAP_node)); 
            memset(data, 0, sizeof(BOGUS_CMAP_node)); 
            if(wmap->setok(&data->data, val)){ 
                idx = hashkey; 
                data->in_use = 1; 
                data->next = wmap->buckets[hashkey].bucket; 
                wmap->buckets[hashkey].bucket = data; 
            } else { 
                free(data); 
            } 
            break; 
        } 
        if(data->in_use){ 
            data = data->next; 
            continue; 
        } 
        if(wmap->setok(&data->data, val)){ 
            idx = hashkey; 
            data->in_use = 1; 
            goto out; 
        } 
        data = data->next; 
    } 
out: 
    pthread_mutex_unlock(&wmap->buckets[hashkey].lock); 
    return idx; 
} 
int BOGUS_CMAP_get(BOGUS_CMAP* wmap, bogus_data* key, void* ret, void (*cb)(void* ret, void* data)){ 
    int idx = -1; 
    BOGUS_CMAP_node* data = NULL; 
    uint64_t hashkey = wmap->hashfunc((uint8_t*)&key->key, wmap->hashsize, wmap->count); 
    pthread_mutex_lock(&wmap->buckets[hashkey].lock); 
    data = wmap->buckets[hashkey].bucket; 
    for(;;){ 
        if(data == NULL){ 
            break; 
        } 
        if(data->in_use){ 
            if(wmap->getok(&data->data, key)){ 
                idx = hashkey; 
                goto out; 
            } 
        } 
        data = data->next; 
    } 
found: 
    if(ret != NULL && cb != NULL){ 
        cb(ret, &data->data); 
    } 
out: 
    pthread_mutex_unlock(&wmap->buckets[hashkey].lock); 
    return idx; 
} 
int BOGUS_CMAP_del(BOGUS_CMAP* wmap, bogus_data* key){ 
    int idx = -1; 
    BOGUS_CMAP_node* data = NULL; 
    uint64_t hashkey = wmap->hashfunc((uint8_t*)&key->key, wmap->hashsize, wmap->count); 
    pthread_mutex_lock(&wmap->buckets[hashkey].lock); 
    data = wmap->buckets[hashkey].bucket; 
    for(;;){ 
        if(data == NULL){ 
            break; 
        } 
        if(data->in_use){ 
            if(wmap->getok(&data->data, key)){ 
                if(wmap->delok(&data->data)){ 
                    data->in_use = 0; 
                    idx = hashkey; 
                    goto out; 
                } 
            } 
        } 
        data = data->next; 
    } 
out: 
    pthread_mutex_unlock(&wmap->buckets[hashkey].lock); 
    return idx; 
} 
void BOGUS_CMAP_clear(BOGUS_CMAP* wmap){ 
    BOGUS_CMAP_node* n = NULL; 
    for(int i = 0 ; i < wmap->count; i++){ 
        pthread_mutex_lock(&wmap->buckets[i].lock); 
        n = wmap->buckets[i].bucket; 
        for(;;){ 
            if(n == NULL){ 
                break; 
            } 
            wmap->buckets[i].bucket = n->next; 
            free(n); 
            n = wmap->buckets[i].bucket; 
        } 
        pthread_mutex_unlock(&wmap->buckets[i].lock); 
    } 
    free(wmap->buckets); 
    free(wmap); 
} 
#endif