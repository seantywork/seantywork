#include "cmap.h"


#define TOTAL_VAL_COUNT 1000000

#ifdef HASHCUSTOM
static inline uint64_t _hashfunc(uint8_t* data, size_t size){}

#else
#define HASHLEN 32
#define HASHTRUNCLEN 8
static inline uint64_t _hashfunc(uint8_t* data, size_t size, uint64_t div){

	uint64_t hashtrunc = 0;
	uint8_t hash[HASHLEN] = {0};
	EVP_MD_CTX *mdctx;
	int digest_len = 0;
	mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
	EVP_DigestUpdate(mdctx, data, size);
	EVP_DigestFinal_ex(mdctx, hash, &digest_len);
	EVP_MD_CTX_free(mdctx);
	memcpy(&hashtrunc, hash, HASHTRUNCLEN);
	
	return hashtrunc % div;
}
#endif

uint64_t _getrandu64(){
    uint8_t data[8];
    uint64_t val;
    getrandom(data, 8, 0);
    memcpy(&val, data, 8);
    return val;
}

BOGUS_CMAP* cmap_alloc(int buck_size, int data_size){

    BOGUS_CMAP* cm = (BOGUS_CMAP*)malloc(sizeof(BOGUS_CMAP));
    cm->buck = (BOGUS_BUCKET*)malloc(buck_size * sizeof(BOGUS_BUCKET));
    cm->buck_size = buck_size;
    for(int i = 0; i < buck_size; i++){
        pthread_mutex_init(&cm->buck[i].lock, NULL);
        for(int j = 0 ; j < data_size; j++){
            BOGUS_DATA* data = (BOGUS_DATA*)malloc(sizeof(BOGUS_DATA));
            memset(data, 0, sizeof(BOGUS_DATA));
            data->next = cm->buck[i].data;
            cm->buck[i].data = data;
        }
    }
    return cm;
}

int cmap_set(BOGUS_CMAP* cm, BOGUS_DATA* val){
    int idx = _hashfunc((void*)val, sizeof(BOGUS_KEY), cm->buck_size);
    pthread_mutex_lock(&cm->buck[idx].lock);
    BOGUS_DATA* data = cm->buck[idx].data;
    for(;;){
        if(data == NULL){
            BOGUS_DATA* newdata = (BOGUS_DATA*)malloc(sizeof(BOGUS_DATA));
            memset(newdata, 0, sizeof(BOGUS_DATA));
            newdata->index = val->index;
            newdata->value = val->value;
            newdata->in_use = 1;
            newdata->next = cm->buck[idx].data;
            cm->buck[idx].data = newdata;
            break;
        }
        if(data->in_use){
            data = data->next;
            continue;
        }
        data->index = val->index;
        data->value = val->value;
        data->in_use = 1;
        break;
    }
    pthread_mutex_unlock(&cm->buck[idx].lock);
    return idx;
}

int cmap_get(BOGUS_CMAP* cm, BOGUS_DATA* key, void* ret, void (*cb)(void* ret, void* data)){
    int idx = _hashfunc((void*)key, sizeof(BOGUS_KEY), cm->buck_size);
    pthread_mutex_lock(&cm->buck[idx].lock);
    BOGUS_DATA* data = cm->buck[idx].data;
    for(;;){
        if(data == NULL){
            idx = -1;
            goto err;
        }
        if(!data->in_use){
            data = data->next;
            continue;
        }
        if(data->index == key->index){
            goto found;
        }
        data = data->next;
    }
found:
    if(ret != NULL && cb != NULL){
        cb(ret, data);
    }
err:
    pthread_mutex_unlock(&cm->buck[idx].lock);
    return idx;
}

int cmap_del(BOGUS_CMAP* cm, BOGUS_DATA* key){
    int idx = _hashfunc((void*)key, sizeof(BOGUS_KEY), cm->buck_size);
    pthread_mutex_lock(&cm->buck[idx].lock);
    BOGUS_DATA* data = cm->buck[idx].data;
    BOGUS_DATA* tmp = NULL;
    for(;;){
        if(data == NULL){
            idx = -1;
            break;
        }
        if(!data->in_use){
            data = data->next;
            continue;
        }
        if(data->index == key->index){
            tmp = data->next;
            memset(data, 0, sizeof(BOGUS_DATA));
            data->next = tmp;
            break;
        }
        data = data->next;
    }
    pthread_mutex_unlock(&cm->buck[idx].lock);
    return idx;
}

void cmap_free(BOGUS_CMAP* cm){

    for(int i = 0 ; i < cm->buck_size; i++){
        BOGUS_DATA* tmp = NULL;
        pthread_mutex_lock(&cm->buck[i].lock);
        for(;;){
            if(cm->buck[i].data == NULL){
                break;
            }
            tmp = cm->buck[i].data->next;
            free(cm->buck[i].data);
            cm->buck[i].data = tmp;
        }
        pthread_mutex_unlock(&cm->buck[i].lock);
    }
    free(cm->buck);
    free(cm);

}

void _get_func(void* ret, void* data){

    BOGUS_DATA* retdata = (BOGUS_DATA*)ret;
    BOGUS_DATA* result = (BOGUS_DATA*)data;
    retdata->value = result->value;
}


void* setter_thread(void* varg){
    pthread_exit(NULL);
}

void* increase_thread(void* varg){
    pthread_exit(NULL);
}

void* decrease_thread(void* varg){
    pthread_exit(NULL);
}

int main(int argc, char** argv){

    return 0;
}