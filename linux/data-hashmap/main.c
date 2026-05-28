#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>


typedef struct elem elem;
typedef struct elem{
    uint64_t id;
    uint64_t flag;
    elem* next;
}elem;

#define IN_USE (1 << 1)
#define IS_IN_USE(x) ((x & IN_USE) == IN_USE)

typedef struct hmap{
    uint64_t size;
    elem** bucks;
}hmap;

uint64_t _hashfunc(void* data, uint32_t datalen){
    uint64_t h = 5381;
    uint8_t* udata = (uint8_t*)data;
    for(int i = 0; i < datalen; i++){
        h = ((h << 5) + h) + udata[i];
    }
    return h;
}
hmap* hmap_create(uint64_t size, int depth){
    hmap* h = malloc(sizeof(hmap));
    h->size = size;
    h->bucks = malloc(sizeof(elem*) * h->size);
    for(int i = 0; i < h->size; i++){
        h->bucks[i] = NULL;
        for(int j = 0; j < depth; j++){
            elem* e = malloc(sizeof(elem));
            memset(e, 0, sizeof(elem));
            e->next = h->bucks[i];
            h->bucks[i] = e;
        }
    }
    return h;
}
int hmap_get(hmap* hm, elem* key, elem* ret){
    int stat = -1;
    uint64_t idx = _hashfunc(&key->id, sizeof(uint64_t)) % hm->size;
    elem* e = hm->bucks[idx];
    for(;;){
        if(e == NULL){
            break;
        }
        if(!IS_IN_USE(e->flag)){
            e = e->next;
            continue;
        }
        if(memcmp(&key->id, &e->id, sizeof(uint64_t)) == 0){
            memcpy(ret, e, sizeof(elem));
            stat = 1;
            break;
        }
        e = e->next;
    }
    return stat;
}
int hmap_set(hmap* hm, elem* val){
    int ret = -1;
    uint64_t idx = _hashfunc(&val->id, sizeof(uint64_t)) % hm->size;
    elem* e = hm->bucks[idx];
    for(;;){
        if(e == NULL){
            e = malloc(sizeof(elem));
            memcpy(e, val, sizeof(elem));
            e->flag = IN_USE;
            e->next = hm->bucks[idx];
            hm->bucks[idx] = e;
            ret = 1;
            break;
        }
        if(IS_IN_USE(e->flag)){
            if(memcmp(&val->id, &e->id, sizeof(uint64_t)) == 0){
                uint64_t flag = e->flag;
                elem* next = e->next;
                memcpy(e, val, sizeof(elem));
                e->flag = flag;
                e->next = next;
                ret = 1;
                break;
            } else {
                e = e->next;
                continue;
            }
        }
        elem* next = e->next;
        memcpy(e, val, sizeof(elem));
        e->flag = IN_USE;
        e->next = next;
        ret = 1;
        break;
    }
    return ret;
}


int main(){
    hmap* h = hmap_create(1024, 4);
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
    printf("success\n");
    return 0;
}