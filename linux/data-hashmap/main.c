#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "map_def.h"

uint64_t _hashfunc(void* data, uint32_t datalen){
    uint64_t h = 5381;
    uint8_t* udata = (uint8_t*)data;
    for(int i = 0; i < datalen; i++){
        h = ((h << 5) + h) + udata[i];
    }
    return h;
}

typedef struct elem{
    uint64_t id;
}elem;

#if NO_MAP_DEF
#define IN_USE (1 << 1)
#define IS_IN_USE(x) ((x & IN_USE) == IN_USE)

typedef struct hmap_node hmap_node;
typedef struct hmap_node{
    elem data;
    uint64_t flag;
    hmap_node* next;
}hmap_node;

typedef struct hmap{
    uint64_t size;
    uint64_t (*hashfunc)(void* data, uint32_t datalen);
    hmap_node** bucks;
}hmap;


hmap* hmap_create(uint64_t size, int depth, uint64_t (*hashfunc)(void* data, uint32_t datalen)){
    hmap* h = malloc(sizeof(hmap));
    h->size = size;
    h->bucks = malloc(sizeof(hmap_node*) * h->size);
    for(int i = 0; i < h->size; i++){
        h->bucks[i] = NULL;
        for(int j = 0; j < depth; j++){
            hmap_node* hn = malloc(sizeof(hmap_node));
            memset(hn, 0, sizeof(hmap_node));
            hn->next = h->bucks[i];
            h->bucks[i] = hn;
        }
    }
    hm->hashfunc = hashfunc;
    return h;
}
int hmap_get(hmap* hm, elem* key, elem* ret){
    int stat = -1;
    uint64_t idx = hm->hashfunc(&key->id, sizeof(uint64_t)) % hm->size;
    hmap_node* e = hm->bucks[idx];
    for(;;){
        if(e == NULL){
            break;
        }
        if(!IS_IN_USE(e->flag)){
            e = e->next;
            continue;
        }
        if(memcmp(&key->id, &e->data.id, sizeof(uint64_t)) == 0){
            memcpy(ret, &e->data, sizeof(elem));
            stat = 1;
            break;
        }
        e = e->next;
    }
    return stat;
}
int hmap_set(hmap* hm, elem* val){
    int ret = -1;
    uint64_t idx = hm->hashfunc(&val->id, sizeof(uint64_t)) % hm->size;
    hmap_node* e = hm->bucks[idx];
    for(;;){
        if(e == NULL){
            e = malloc(sizeof(hmap_node));
            memcpy(&e->data, val, sizeof(elem));
            e->flag = IN_USE;
            e->next = hm->bucks[idx];
            hm->bucks[idx] = e;
            ret = 1;
            break;
        }
        if(IS_IN_USE(e->flag)){
            if(memcmp(&val->id, &e->data.id, sizeof(uint64_t)) == 0){
                memcpy(&e->data, val, sizeof(elem));
                ret = 1;
                break;
            } else {
                e = e->next;
                continue;
            }
        }
        memcpy(&e->data, val, sizeof(elem));
        e->flag = IN_USE;
        ret = 1;
        break;
    }
    return ret;
}

#endif

DECL_MAP(hmap, elem)
DEF_MAP(hmap, elem, uint64_t, id)

int main(){
    hmap* h = hmap_create(1024, 4, _hashfunc);
    int a = 0;
    int b = 0;
    for(int i = 0 ; i < 1024; i++){
        elem e;
        e.id = i;
        if(hmap_set(h, &e) < 0){
            printf("failed to set: %d\n", i);
            return -1;
        }
        a += i;
    }
    for(int i = 0; i < 1024; i++){
        elem e;
        e.id = i;
        if(hmap_get(h, &e, &e) < 0){
            printf("failed to get: %d\n", i);
            return -1;
        }
        b += i;
    }
    if(a != b){
        printf("failed to validate: %d != %d\n", a, b);
        return -1;
    }
    for(int i = 0; i < 1024; i++){
        elem e;
        e.id = i;
        hmap_del(h, &e);
    }
    for(int i = 0; i < 1024; i++){
        elem e;
        e.id = i;
        if(hmap_get(h, &e, &e) > 0){
            printf("deleted el should not be gettable: %d\n", i);
            return -1;
        }
    }
    printf("success\n");
    return 0;
}