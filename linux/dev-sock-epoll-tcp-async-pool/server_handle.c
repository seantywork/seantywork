#include "server_ep.h"

DEF_QUEUE(work_queue, job_t*)

job_t* new_job(){
    job_t* j = (job_t*)malloc(sizeof(job_t));
    memset(j, 0, sizeof(job_t));
    return j;
}

void free_job(job_t* j){
    if(j->data != NULL){
        free(j->data);
        j->data = NULL;
    }
    free(j);
}

int make_socket_non_blocking (int sfd){
  int flags, s;

  flags = fcntl (sfd, F_GETFL, 0);
  if (flags == -1)
    {
      perror ("fcntl get");
      return -1;
    }

  flags |= O_NONBLOCK;
  s = fcntl (sfd, F_SETFL, flags);
  if (s == -1)
    {
      perror ("fcntl set");
      return -2;
    }

  return 0;
}


void* worker(void *varg){
    worker_t* worker = (worker_t*)varg;
    work_queue_bucket* wq = (work_queue_bucket*)worker->work_queue;
    job_t* job = NULL;
    job_kind jk = JK_NONE;
    printf("worker ready: %d\n", worker->id);
    while(1){
        work_queue_de(wq, &job);
        printf("wk start: %d\n", worker->id);
        if(job->job(job->data, &jk) == JOB_DONE){
            free_job(job);
            job = NULL;
        } else {
            if(jk == JK_NONE){
                printf("wk invalid: none while keep?: %d\n", worker->id);
                free_job(job);
                continue;
            }
            switch (jk){
                case JK_DATA:
                    printf("next: data\n");
                    job->job = handle_data;
                    break;
                case JK_WRITE:
                    printf("next: write\n");
                    job->job = handle_write;
                    break;
                default:
                    printf("wk invalid: id %d, jk: %d\n", worker->id, jk);
                    free_job(job);
                    continue;     
            }
            work_queue_en(wq, &job);
        }
        printf("wk done: %d\n", worker->id);
    }
    pthread_exit(NULL);
}


uint8_t handle_conn(void* data, job_kind* next){
    uint8_t result = JOB_DONE;
    conn_context_t* ctx = (conn_context_t*)data;
    struct epoll_event event;
    while(TRUE){
        struct sockaddr in_addr;
        socklen_t in_len;
        int infd;
        in_len = sizeof(in_addr);
        infd = accept(ctx->fd, &in_addr, &in_len);
        if(infd == -1){
            if(
                (errno == EAGAIN) ||
                (errno == EWOULDBLOCK)
            ){
                printf("all incoming connections handled\n");
                break;
            } else{
                printf("errno: %d\n", errno);
                printf("error handling incoming connection\n");
                break;
            }
        }

        if(make_socket_non_blocking(infd) < 0){
            printf("failed new conn non block\n");
            break;
        }
        memset(&event, 0, sizeof(struct epoll_event));
        event.data.fd = infd;
        event.events = EPOLLIN | EPOLLET;
        if (epoll_ctl(ctx->eplfd, EPOLL_CTL_ADD, infd, &event) < 0){
            printf("handle epoll add failed\n");
            break;
        }  else {
            printf("handle epoll add success\n");
        }
    }
    *next = JK_NONE;
    return result;
}


uint8_t handle_read(void* data, job_kind* next){
    read_context_t* ctx = (read_context_t*)data;
    int done = JOB_KEEP;
    int valread = 0;
    ctx->buff = (uint8_t*)malloc(MAX_BUFF);
    ctx->datalen = 0; 
    struct sockaddr_in peeraddr;
    socklen_t peerlen;
    peerlen = sizeof(peeraddr);
    while(valread < MAX_BUFF){
        int n = 0;
        n = read(ctx->fd, ctx->buff + valread, MAX_BUFF - valread);
        if(n == -1){
            if(errno != EAGAIN){
                printf("handle read error\n");
            }    
            done = JOB_DONE;
            break;
        } else if (n == 0){
            getpeername(ctx->fd, (SA*)&peeraddr, &peerlen);
            printf("client disconnected: ip=%s, port=%d\n",
                inet_ntoa(peeraddr.sin_addr),
                ntohs(peeraddr.sin_port)
            );
            free(ctx->buff);
            done = JOB_DONE;
            break;
        }
        valread += n;    
    }
    if (done == JOB_DONE){
        close(ctx->fd);
        printf("closed sock\n");
        return done;
    }
    printf("read: %d\n", valread);
    ctx->datalen = (uint32_t)valread;
    *next = JK_DATA;
    return done;
}


uint8_t handle_data(void *data, job_kind* next){
    int done = JOB_KEEP;
    read_context_t* ctx = (read_context_t*)data;
    printf("data: %d\n", ctx->datalen);
    *next = JK_WRITE;
    return done;
}

uint8_t handle_write(void *data, job_kind* next){
    int done = JOB_DONE;
    read_context_t* ctx = (read_context_t*)data;
    int wval = write(ctx->fd, ctx->buff, ctx->datalen);
    printf("write: %d\n", wval);
    *next = JK_NONE;
    free(ctx->buff);
    return done;
}


bool _atomic_compare_exchange(int* ptr, int compare, int exchange) {
    return __atomic_compare_exchange_n(ptr, &compare, exchange,
            0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
}
void _atomic_store(int* ptr, int value) {
    __atomic_store_n(ptr, value, __ATOMIC_SEQ_CST);
}
