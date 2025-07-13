#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

typedef struct node {

    int val;
    void* prev;
    void* next;

}node;

typedef struct bucket {

    pthread_mutex_t lock;
    int max;
    int count;
    node* node;
    node* tail;

}bucket;



bucket* make_queue(int max){

    bucket* q = (bucket*)malloc(sizeof(bucket));

    memset(q, 0, sizeof(bucket));

    pthread_mutex_init(&q->lock, NULL);
    q->max = max;

    return q;

}

void delete_queue(bucket* q){

    if(q == NULL){
        return;
    }

    node* data = q->node;

    for(;;){

        if(q->node == NULL){
            break;
        }

        data = q->node->next;

        free(q->node);

        q->node = data;

    }

    free(q);
}

void enqueue(bucket* q, int val){

    for(;;){
        pthread_mutex_lock(&q->lock);

        if(q->count == q->max){
            pthread_mutex_unlock(&q->lock);
            continue;
        }

        node* newn = (node*)malloc(sizeof(node));
        newn->val = val;
        q->count += 1;
        newn->prev = NULL;
        if(q->count == 1){
            newn->next = NULL;
            q->tail = newn;
            q->node = newn;            
        } else {
            newn->next = q->node;
            q->node->prev = newn;
            q->node = newn;
        }

        pthread_mutex_unlock(&q->lock);
        break;
    }
}

int dequeue(bucket* q){

    int val;

    for(;;){
        pthread_mutex_lock(&q->lock);

        if(q->count == 0){
            pthread_mutex_unlock(&q->lock);
            continue;
        }

        val = q->tail->val;
        q->count -= 1;
        if(q->count == 0){
            free(q->node);
            q->node = NULL;
            q->tail = NULL;
        } else {
            node* oldn = q->tail->prev;
            free(q->tail);
            q->tail = oldn;

        }

        pthread_mutex_unlock(&q->lock);
        break;
    }

    return val;
}


int do_enqueue(bucket* q){

    int total = 0;

    for(int i = 0 ; i < 100; i++){

        enqueue(q, i);

        total += i;
    }

    return total;
}

void do_dequeue(bucket* q, int total){

    int tmp = 0;

    for(;;){

        tmp += dequeue(q);

        if(tmp == total){
            return;
        }
    }

}

int main(){

    bucket* q = make_queue(100);

    int total = do_enqueue(q);

    printf("enqueue total: %d\n", total);

    do_dequeue(q, total);

    printf("dequeue successful\n");

    delete_queue(q);

    return 0;

}