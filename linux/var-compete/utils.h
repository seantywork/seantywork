#ifndef _CP_UTILS_H_
#define _CP_UTILS_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define __mflag_IN_USE (1 << 1)
#define __mflag_test_IN_USE(x) ((x & __mflag_IN_USE) == __mflag_IN_USE)

#define DECL_MAP(__map_t, __data_t) \
typedef struct __map_t##_node __map_t##_node; \
typedef struct __map_t##_node{ \
    __data_t data; \
    uint64_t flag; \
    __map_t##_node* next; \
}__map_t##_node; \
typedef struct __map_t{ \
    uint64_t size; \
    uint64_t (*hashfunc)(void* data, uint32_t datalen); \
    __map_t##_node** bucks; \
}__map_t; \
__map_t* __map_t##_create(uint64_t size, int depth, uint64_t (*hashfunc)(void* data, uint32_t datalen)); \
int __map_t##_get(__map_t* hm, __data_t* key, __data_t* ret); \
int __map_t##_set(__map_t* hm, __data_t* val); \

#define DEF_MAP(__map_t, __data_t, __key_t, __key_name) \
__map_t* __map_t##_create(uint64_t size, int depth, uint64_t (*hashfunc)(void* data, uint32_t datalen)){ \
    __map_t* h = malloc(sizeof(__map_t)); \
    h->size = size; \
    h->bucks = malloc(sizeof(__map_t##_node*) * h->size); \
    for(int i = 0; i < h->size; i++){ \
        h->bucks[i] = NULL; \
        for(int j = 0; j < depth; j++){ \
            __map_t##_node* hn = malloc(sizeof(__map_t##_node)); \
            memset(hn, 0, sizeof(__map_t##_node)); \
            hn->next = h->bucks[i]; \
            h->bucks[i] = hn; \
        } \
    } \
    h->hashfunc = hashfunc; \
    return h; \
} \
int __map_t##_get(__map_t* hm, __data_t* key, __data_t* ret){ \
    int stat = -1; \
    uint64_t idx = hm->hashfunc(&key->__key_name, sizeof(__key_t)) % hm->size; \
    __map_t##_node* e = hm->bucks[idx]; \
    for(;;){  \
        if(e == NULL){ \
            break; \
        } \
        if(!__mflag_test_IN_USE(e->flag)){ \
            e = e->next; \
            continue; \
        } \
        if(memcmp(&key->__key_name, &e->data.__key_name, sizeof(__key_t)) == 0){ \
            memcpy(ret, &e->data, sizeof(__data_t)); \
            stat = 1; \
            break; \
        } \
        e = e->next; \
    } \
    return stat; \
} \
int __map_t##_set(__map_t* hm, __data_t* val){ \
    int ret = -1; \
    uint64_t idx = hm->hashfunc(&val->__key_name, sizeof(__key_t)) % hm->size; \
    __map_t##_node* e = hm->bucks[idx]; \
    for(;;){ \
        if(e == NULL){ \
            e = malloc(sizeof(__map_t##_node)); \
            memcpy(&e->data, val, sizeof(__data_t)); \
            e->flag = __mflag_IN_USE; \
            e->next = hm->bucks[idx]; \
            hm->bucks[idx] = e; \
            ret = 1; \
            break; \
        } \
        if(__mflag_test_IN_USE(e->flag)){ \
            if(memcmp(&val->__key_name, &e->data.__key_name, sizeof(__key_t)) == 0){ \
                memcpy(&e->data, val, sizeof(__data_t)); \
                ret = 1; \
                break; \
            } else { \
                e = e->next; \
                continue; \
            } \
        } \
        memcpy(&e->data, val, sizeof(__data_t)); \
        e->flag = __mflag_IN_USE; \
        ret = 1; \
        break; \
    } \
    return ret; \
}\


uint64_t _hashfunc(void* data, uint32_t datalen){
    uint64_t h = 5381;
    uint8_t* udata = (uint8_t*)data;
    for(int i = 0; i < datalen; i++){
        h = ((h << 5) + h) + udata[i];
    }
    return h;
}


#endif