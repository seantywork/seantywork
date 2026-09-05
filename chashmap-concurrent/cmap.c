#include "cmap.h"
#include "cmap_def.h"

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



uint8_t _set_ok(void* data, void* val){
    bogus_data* d = (bogus_data*)data;
    bogus_data* s = (bogus_data*)val;
    memcpy(d, s, sizeof(bogus_data));
    return 1;
}

uint8_t _get_ok(void* data, void* key){
    bogus_data* d = (bogus_data*)data;
    bogus_data* s = (bogus_data*)key;
    if(d->index == s->index){
        return 1;
    }
    return 0;
}

uint8_t _del_ok(void* data){
    bogus_data* d = (bogus_data*)data;
    memset(d, 0, sizeof(bogus_data));
    return 1;
}



pthread_mutex_t plock;
int inc_done_count = 0;
int dec_done_count = 0;

void _inc_func(void* ret, void* data){

    bogus_data* retdata = (bogus_data*)ret;
    bogus_data* result = (bogus_data*)data;
    result->value += result->index;
}
void _dec_func(void* ret, void* data){
    bogus_data* retdata = (bogus_data*)ret;
    bogus_data* result = (bogus_data*)data;
    result->value -= result->index;
}



void* increase_thread(void* varg){
    BOGUS_CMAP* cm = (BOGUS_CMAP*)varg;
    bogus_data key;
    for(int i = 0; i < TOTAL_VAL_COUNT; i++){
        key.index = i;
        if(BOGUS_CMAP_get(cm, &key, &key, _inc_func) < 0){
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
    bogus_data key;
    for(int i = 0; i < TOTAL_VAL_COUNT; i++){
        key.index = i;
        if(BOGUS_CMAP_get(cm, &key, &key, _dec_func) < 0){
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

    BOGUS_CMAP* cm = BOGUS_CMAP_create(BUCK_SIZE, DATA_SIZE, _hashfunc, _get_ok, _set_ok, _del_ok);
    if(cm == NULL){
        printf("failed to create cmap\n");
        return -1;
    }
    printf("created map\n");
    printf("inserting data...\n");
    for(int i = 0 ; i < TOTAL_VAL_COUNT; i++){
        bogus_data data;
        data.index = i;
        data.value = 0;
        if(BOGUS_CMAP_set(cm, &data) < 0){
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
    for(int i = 0 ; i < cm->count; i++){
        BOGUS_CMAP_node* data = cm->buckets[i].bucket;
        for(;;){
            if(data == NULL){
                break;
            }
            if(data->data.value){
                printf("data invalid at: buck: %d - index: %lu - value: %lu\n", i, data->data.index, data->data.value);
                goto done;
            }
            data = data->next;
        }
    }
    printf("all data is valid\n");
    result = 0;
done:
    BOGUS_CMAP_clear(cm);
    return result;
}