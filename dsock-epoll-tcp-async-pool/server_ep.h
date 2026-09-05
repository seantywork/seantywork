#ifndef SERVER_ST_HEADER
#define SERVER_ST_HEADER

#include <stdio.h> 
#include <netdb.h> 
#include <netinet/in.h> 
#include <stdlib.h> 
#include <string.h> 
#include <sys/socket.h> 
#include <sys/types.h> 
#include <unistd.h> 
#include <time.h>
#include <stdbool.h>
//#include <stdatomic.h>
// ep headers
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>
#include <arpa/inet.h>
#include <pthread.h>



#endif // SERVER_ST_HEADER

#ifndef SERVER_EP_HEADER_DEF
#define SERVER_EP_HEADER_DEF

#define TRUE 1
#define FALSE 0
#define MAX_BUFF 1024 
#define MAX_CONN 80
#define PORT 8080 
#define SA struct sockaddr 
   

extern struct sockaddr_in SERVADDR;
extern int SERVLEN;

extern int SOCKFD;
extern int EPLFD;
extern int MAX_SD;

extern int OPT;

extern struct epoll_event EVENT;
extern struct epoll_event *CLIENT_SOCKET;

#define MAX_WORKER 16
typedef struct worker_t {
    int id;
    void* work_queue;
} worker_t;
extern pthread_t *WORK_TID;
extern worker_t *WORKERS;

#define MAX_JOB 8192

typedef enum job_kind {
    JOB_NONE,
    JOB_DONE,
    JOB_CONN,
    JOB_READ,
    JOB_DATA,
    JOB_WRITE,
} job_kind;

typedef struct job_t {
    void* data;
    job_kind (*job)(void* data);
} job_t;

typedef struct conn_context_t {
    int result;
    int fd;
    int eplfd;
}conn_context_t;

typedef struct read_context_t {
    int result;
    int fd;
    uint32_t datalen;
    uint8_t* buff;
}read_context_t;


job_t* new_job();
void free_job(job_t* j);
int make_socket_non_blocking (int);
void* worker(void* varg);
job_kind handle_conn(void* data);
job_kind handle_read(void* data);
job_kind handle_data(void* data);
job_kind handle_write(void* data);

bool _atomic_compare_exchange(int* ptr, int compare, int exchange);
void _atomic_store(int* ptr, int value);

#define DECL_QUEUE(__q_t, __data_t) \
typedef struct __q_t##_node __q_t##_node; \
struct __q_t##_node { \
    uint32_t datalen; \
    uint8_t in_use; \
    uint8_t rsvd[3]; \
	__data_t data; \
	__q_t##_node* prev; \
	__q_t##_node* next; \
}; \
typedef struct __q_t##_bucket { \
    int proceed; \
	uint32_t limit; \
	pthread_mutex_t lock; \
	pthread_cond_t sig; \
	__q_t##_node* qhead; \
	__q_t##_node* qtail; \
} __q_t##_bucket; \
__q_t##_bucket* __q_t##_make(int max); \
void __q_t##_delete(__q_t##_bucket* q); \
void __q_t##_en(__q_t##_bucket* q, __data_t* data); \
void __q_t##_de(__q_t##_bucket* q, __data_t* data); \


#define DEF_QUEUE(__q_t, __data_t) \
__q_t##_bucket* __q_t##_make(int max){ \
    __q_t##_bucket* q = (__q_t##_bucket*)malloc(sizeof(__q_t##_bucket)); \
    memset(q, 0, sizeof(__q_t##_bucket)); \
    pthread_mutex_init(&q->lock, NULL); \
    pthread_cond_init(&q->sig, NULL); \
    for(int i = 0; i < max; i++){ \
        __q_t##_node* n = (__q_t##_node*)malloc(sizeof(__q_t##_node)); \
        memset(n, 0, sizeof(__q_t##_node)); \
        memset(&n->data, 0, sizeof(__data_t)); \
        n->datalen = sizeof(__data_t); \
        if(i == 0){ \
            q->qhead = n; \
            q->qtail = n; \
        } else { \
            q->qtail->next = n; \
            q->qtail = q->qtail->next; \
        } \
    } \
    q->qtail->next = q->qhead; \
    q->qtail = q->qhead; \
    q->limit = max; \
    return q; \
} \
void __q_t##_delete(__q_t##_bucket* q){ \
    if(q == NULL){ \
        return; \
    } \
    __q_t##_node* data = q->qhead; \
    pthread_mutex_lock(&q->lock); \
    for(int i = 0; i < q->limit; i++){ \
        __q_t##_node* tmp = data->next; \
        free(data); \
        data = tmp; \
    } \
    pthread_mutex_unlock(&q->lock); \
    free(q); \
} \
void __q_t##_en(__q_t##_bucket* q, __data_t* data){ \
    for(;;){ \
        pthread_mutex_lock(&q->lock); \
        if((q->qhead == q->qtail) && (q->qhead->in_use == 1)){ \
            pthread_cond_wait(&q->sig, &q->lock); \
            if((q->qhead == q->qtail) && (q->qhead->in_use == 1)){ \
                pthread_mutex_unlock(&q->lock); \
                continue; \
            } \
        } \
        memcpy(&q->qtail->data, data, q->qtail->datalen); \
        if((q->qhead == q->qtail) && (q->qhead->in_use != 1)){ \
            pthread_cond_broadcast(&q->sig); \
        } \
        q->qtail->in_use = 1; \
        q->qtail = q->qtail->next; \
        pthread_mutex_unlock(&q->lock); \
        break; \
    } \
} \
void __q_t##_de(__q_t##_bucket* q, __data_t* data){ \
    for(;;){ \
        pthread_mutex_lock(&q->lock); \
        if((q->qhead == q->qtail) && (q->qhead->in_use != 1)){ \
            pthread_cond_wait(&q->sig, &q->lock); \
            if((q->qhead == q->qtail) && (q->qhead->in_use != 1)){ \
                pthread_mutex_unlock(&q->lock); \
                continue; \
            } \
        } \
        memcpy(data, &q->qhead->data, q->qhead->datalen); \
        if((q->qhead == q->qtail) && (q->qhead->in_use == 1)){ \
            pthread_cond_broadcast(&q->sig); \
        } \
        q->qhead->in_use = 0; \
        q->qhead = q->qhead->next; \
        pthread_mutex_unlock(&q->lock); \
        break; \
    } \
} \

DECL_QUEUE(work_queue, job_t*)



#endif