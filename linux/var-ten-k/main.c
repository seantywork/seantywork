#include "tenk.h"


char mode = 's';
char server_mode = 's';

int client_num = MAXCLIENT;
uint8_t** client_buff = NULL;

int wfds[MAXCLIENT] = {0};
uint8_t wbuff[MAXCLIENT/CLIENTS_PER_THREAD][MAXBUFFLEN];
atomic_uint_fast8_t wdones[MAXCLIENT / CLIENTS_PER_THREAD];



pthread_mutex_t lock;

static void help(){

    printf("arguments: mode [address|server_mode]\n");
        
    printf("mode: c - client, s - server\n");
    printf("address: server address in client mode\n");
    printf("server_mode: s - select, p - poll, e - epoll\n");
}

int main(int argc, char** argv){

    int result = -1;

    int sockfd;
    int opt = 1;
    struct sockaddr_in servaddr;

    if(argc != 3){

        help();

        return -1;
    }

    if(strcmp(argv[1], "c") == 0){

        mode = 'c';

    } else if (strcmp(argv[1], "s") == 0){

        mode = 's';
    } else {

        printf("invalid mode: %s\n", argv[1]);
        help();

        return -1;

    }

    if(mode == 'c'){

        printf("client mode: address: %s\n", argv[2]);

        pthread_t tids[MAXCLIENT / CLIENTS_PER_THREAD];
        int ids[MAXCLIENT / CLIENTS_PER_THREAD];

        int connfd;
        struct sockaddr_in servaddr;

        printf("creating connections: %d\n", MAXCLIENT);

        for(int i = 0; i < MAXCLIENT; i++){

            connfd = socket(AF_INET, SOCK_STREAM, 0);
            if (connfd == -1) {
                printf("client socket creation failed: %d\n", i);
                result = -1;
                break;    
            }
        
            memset(&servaddr, 0, sizeof(servaddr));

            servaddr.sin_family = AF_INET;
            servaddr.sin_addr.s_addr = inet_addr(argv[2]);
            servaddr.sin_port = htons(PORT);
         
            if (connect(connfd, (struct sockaddr*)&servaddr, sizeof(servaddr))!= 0) {
                printf("connection with the server failed: %d\n", i);
                result = -1;
                break;
            }

            if(i % 100 == 0){
                printf("connectons : %d...\n", i);
            }

            wfds[i] = connfd;

        }

        printf("created connections: %d\n", MAXCLIENT);

        int thread_count = MAXCLIENT / CLIENTS_PER_THREAD;
        
        printf("creating threads: %d\n", thread_count);

        for(int i = 0; i < thread_count; i++){

            ids[i] = i;
            wdones[i] = 0;
            pthread_create(&tids[i], NULL, run_client_thread, (void*)&ids[i]);

        }
        
        printf("created threads: %d\n", thread_count);

        printf("running...\n");

        struct timeval t1, t2;
    
        gettimeofday(&t1, NULL);

        gettimeofday(&t2, NULL);
    
        while(1){

            int count = 0;

            for(int i = 0 ; i < thread_count; i++){

                if(wdones[i] == 1){
                    count += 1;
                }

            }

            if(count == thread_count){

                printf("done\n");
                break;
            }
        }

        gettimeofday(&t2, NULL);
    
                
        uint32_t seconds = t2.tv_sec - t1.tv_sec;      
        uint32_t ms = (t2.tv_usec - t1.tv_usec) / 1000;
        
        printf("sec: %lu ms: %lu\n", seconds, ms);

    }

    if(mode == 's'){

        if(strcmp(argv[2], "s") == 0){

            server_mode = 's';
        } else if(strcmp(argv[2], "p") == 0){
    
            server_mode = 'p';
        } else if(strcmp(argv[2], "e") == 0){
    
            server_mode = 'e';
        } else {
    
            printf("invalid server mode: %s\n", argv[2]);
            help();
    
            return -1;
        }

        client_buff = (uint8_t**)malloc(client_num * sizeof(uint8_t*));

        for(int i = 0; i < client_num; i++){

            client_buff[i] = (uint8_t*)malloc(MAXBUFFLEN * sizeof(uint8_t));

        }


        sockfd = socket(AF_INET, SOCK_STREAM, 0); 
        if (sockfd == -1) { 
            printf("socket creation failed\n"); 
            return -1;
        } else {
            printf("socket successfully created\n"); 
        }
    
        if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)) < 0 ){  
            printf("setsockopt failed\n");   
            return -1;   
        }   
        
        memset(&servaddr, 0, sizeof(servaddr));
     
        servaddr.sin_family = AF_INET; 
        servaddr.sin_addr.s_addr = htonl(INADDR_ANY); 
        servaddr.sin_port = htons(PORT); 
       
        if ((bind(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr))) != 0) { 
            printf("socket bind failed\n"); 
            return -1; 
        } 
       
        if(make_socket_non_blocking(sockfd) < 0){
            printf("non-blocking failed\n");
            return -1;
        }
        
        if ((listen(sockfd, client_num + 1)) != 0) { 
            printf("listen failed\n"); 
            return -1;
        } 
        if(server_mode == 's'){
    
            result = run_select(sockfd, &servaddr);
    
        } else if (server_mode == 'p') {
    
            result = run_poll(sockfd, &servaddr);
    
        } else if (server_mode == 'e') {
    
            result = run_epoll(sockfd, &servaddr);
        }

        for(int i = 0 ; i < client_num; i++){

            free(client_buff[i]);

        }

        free(client_buff);
    }


    return result;
}