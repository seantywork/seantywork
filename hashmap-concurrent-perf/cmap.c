#include "cmap.h"

#define TOTAL_THREAD_COUNT 10
#define TOTAL_VAL_COUNT 1000000
#define BUCK_SIZE 1024 
#define DATA_SIZE 512


#define HASHLEN 32
#define HASHTRUNCLEN 8
#if HASHSHA
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
#elif HASHFNV
#define FNV1_64_INIT ((uint64_t)0xcbf29ce484222325ULL)
static inline uint64_t _hashfunc(uint8_t* data, size_t size, uint64_t div){
    unsigned char *bp = (unsigned char *)data;	/* start of buffer */
    unsigned char *be = bp + size;		/* beyond end of buffer */
	uint64_t hval = FNV1_64_INIT;
    /*
     * FNV-1 hash each octet of the buffer
     */
    while (bp < be) {

	/* multiply by the 64 bit FNV magic prime mod 2^64 */
#if defined(NO_FNV_GCC_OPTIMIZATION)
		hval *= FNV_64_PRIME;
#else /* NO_FNV_GCC_OPTIMIZATION */
		hval += (hval << 1) + (hval << 4) + (hval << 5) +
			(hval << 7) + (hval << 8) + (hval << 40);
#endif /* NO_FNV_GCC_OPTIMIZATION */

	/* xor the bottom with the current octet */
		hval ^= (uint64_t)*bp++;
    }

    /* return our new hash value */
    return hval % div;
}
#endif



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

pthread_mutex_t plock;
int inc_done_count = 0;
int dec_done_count = 0;

void _inc_func(void* ret, void* data){

    BOGUS_DATA* retdata = (BOGUS_DATA*)ret;
    BOGUS_DATA* result = (BOGUS_DATA*)data;
    result->value += result->index;
}
void _dec_func(void* ret, void* data){

    BOGUS_DATA* retdata = (BOGUS_DATA*)ret;
    BOGUS_DATA* result = (BOGUS_DATA*)data;
    result->value -= result->index;
}

void* increase_thread(void* varg){
    BOGUS_CMAP* cm = (BOGUS_CMAP*)varg;
    BOGUS_DATA key;
    for(int i = 0; i < TOTAL_VAL_COUNT; i++){
        key.index = i;
        if(cmap_get(cm, &key, &key, _inc_func) < 0){
            printf("error getting at inc thread\n");
            goto done;
        }
    }
    pthread_mutex_lock(&plock);
    printf("inc done: %d\n", inc_done_count);
    inc_done_count += 1;
    pthread_mutex_unlock(&plock);

done:
    pthread_exit(NULL);
}

void* decrease_thread(void* varg){
    BOGUS_CMAP* cm = (BOGUS_CMAP*)varg;
    BOGUS_DATA key;
    for(int i = 0; i < TOTAL_VAL_COUNT; i++){
        key.index = i;
        if(cmap_get(cm, &key, &key, _dec_func) < 0){
            printf("error getting at dec thread\n");
            goto done;
        }
    }
    pthread_mutex_lock(&plock);
    printf("dec done: %d\n", dec_done_count);
    dec_done_count += 1;
    pthread_mutex_unlock(&plock);

done:
    pthread_exit(NULL);
}

int main(int argc, char** argv){

    pthread_t inc_t[TOTAL_THREAD_COUNT];
    pthread_t dec_t[TOTAL_THREAD_COUNT];
    struct timeval start;
    struct timeval end;
    int result = -1;

    printf("inserting data...\n");
    BOGUS_CMAP* cm = cmap_alloc(BUCK_SIZE, DATA_SIZE);
    for(int i = 0 ; i < TOTAL_VAL_COUNT; i++){
        BOGUS_DATA data;
        data.index = i;
        data.value = 0;
        if(cmap_set(cm, &data) < 0){
            printf("failed to set value: %d\n", i);
            goto done;
        }     
    }
    pthread_mutex_init(&plock, NULL);
    for(int i = 0; i < TOTAL_THREAD_COUNT; i++){
        if(pthread_create(&inc_t[i], NULL, increase_thread, (void*)cm) < 0){
            printf("failed to create increase thread: %d\n", i);
            goto done;
        }   
        if(pthread_create(&dec_t[i], NULL, decrease_thread, (void*)cm) < 0){
            printf("failed to create decrease thread: %d\n", i);
            goto done;
        }
    }
    gettimeofday(&start, NULL);
    printf("running...\n");
    for(int i = 0 ; i < TOTAL_THREAD_COUNT; i++){
        pthread_join(inc_t[i], NULL);
        pthread_join(dec_t[i], NULL);
    }
    printf("completed\n");
    gettimeofday(&end, NULL);
    printf("took: %lu us\n", (end.tv_sec - start.tv_sec) * 1000000 + end.tv_usec - start.tv_usec);
    for(int i = 0 ; i < cm->buck_size; i++){
        BOGUS_DATA* data = cm->buck[i].data;
        for(;;){
            if(data == NULL){
                break;
            }
            if(data->value){
                printf("data invalid at: buck: %d - index: %lu - value: %lu\n", i, data->index, data->value);
                goto done;
            }
            data = data->next;
        }
    }
    printf("all data is valid\n");
    result = 0;
done:
    cmap_free(cm);
    return result;
}