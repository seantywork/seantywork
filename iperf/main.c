#include "iperf_s.h"


char mode = 's';
unsigned short port = 5001;
int client_num = 1;
int timeout = 5;

int ctl_fd = 0;
uint8_t client_buff[MAXCLIENT][MAXBUFFLEN];

pthread_mutex_t lock;

static void help(){

    printf("arguments: mode port client_num timeout\n");
        
    printf("mode: s - select, p - poll, e - epoll\n");
}

int main(int argc, char** argv){

    int result = -1;

    int sockfd;
    int opt = 1;
    struct sockaddr_in servaddr;

    if(argc != 5){

        help();

        return -1;
    }

    memset(client_buff, 0, MAXCLIENT * MAXBUFFLEN);

    if(strcmp(argv[1], "s") == 0){

        mode = 's';
    } else if(strcmp(argv[1], "p") == 0){

        mode = 'p';
    } else if(strcmp(argv[1], "e") == 0){

        mode = 'e';
    } else {

        printf("invalid mode: %s\n", argv[1]);
        help();

        return -1;
    }

    sscanf(argv[2], "%hd", &port);

    printf("port to use: %hd\n", port);

    sscanf(argv[3], "%d", &client_num);

    printf("client num: %d\n", client_num);

    if(client_num > MAXCLIENT){

        printf("too many clients: %d\n", client_num);

        return -1;
    }

    sscanf(argv[4], "%d", &timeout);

    printf("timeout: %d\n", timeout);

    pthread_mutex_init(&lock, NULL);

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
    servaddr.sin_port = htons(port); 
   
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
    if(mode == 's'){

        result = run_select(sockfd, &servaddr);

    } else if (mode == 'p') {

        result = run_poll(sockfd, &servaddr);

    } else if (mode == 'e') {

        result = run_epoll(sockfd, &servaddr);
    }

    return result;
}