#include "iperf_s.h"


static uint8_t ctl_hello[37] = {0};
static uint8_t ctl_hellow_answer[1] = {0x09};
static uint32_t ctl_info_size = 0;
static uint8_t* ctl_info = NULL;
static uint8_t ctl_info_answer[1] = {0x0a};
static uint8_t ctl_start_1[1] = {0x01};
static uint8_t ctl_start_2[1] = {0x02};
static uint8_t ctl_end_1[1] = {0x0d};
static uint8_t ctl_end_2[1] = {0x0e};

static uint8_t hello[37] = {0};

int make_socket_non_blocking(int sfd){
    int flags, s;
  
    flags = fcntl (sfd, F_GETFL, 0);
    if (flags == -1){
        printf("fcntl get");
        return -1;
    }
  
    flags |= O_NONBLOCK;
    s = fcntl (sfd, F_SETFL, flags);
    if (s == -1){
        printf("fcntl set");
        return -2;
    } 
    return 0;
}

void* ctl_runner(void* varg){

    int ctl_fd = *(int*)varg;

    sleep(timeout);
    write(ctl_fd, ctl_end_1, 1);
    read(ctl_fd, &ctl_info_size, 4);
    
    uint32_t isize = ntohl(ctl_info_size);
    ctl_info = (uint8_t*)malloc(isize * sizeof(uint8_t));
    read(ctl_fd, ctl_info, isize);
    printf("%s\n",ctl_info);
    write(ctl_fd, &ctl_info_size, 4);
    write(ctl_fd, ctl_info, isize);
    write(ctl_fd, ctl_end_2, 1);
    free(ctl_info);
    
    //close(ctl_fd);


}

int run_select(int fd, struct sockaddr_in* servaddr){

    int connections = 0;

    pthread_t tid;

    int ctl_fd = 0;
    int max_fd = 0;
    int event = 0;
    fd_set readfds;
    int servlen;
    int client_fds[MAXCLIENT] = {0};
    int valread;
    int n;
    int client_fd;



    servlen = sizeof(*servaddr);   
    
    while(1){

        FD_ZERO(&readfds);
        FD_SET(fd, &readfds);
        max_fd = fd;

        for(int i = 0; i < client_num; i++){
            client_fd = client_fds[i];

            if(client_fd > 0){
                FD_SET(client_fd, &readfds);
            }
            if(client_fd > max_fd){
                max_fd = client_fd;
            }
            
        }

        event = select(max_fd + 1, &readfds, NULL, NULL, NULL);



        if ((event < 0 ) && (errno != EINTR)){
            printf("select error\n");
            break;
        }

        do {
            if(FD_ISSET(fd, &readfds)){
                int added = 0;
                int client_fd = accept(fd, (struct sockaddr*)servaddr, (socklen_t*)&servlen);
                if(ctl_fd == 0){

                    ctl_fd = client_fd;

                    read(ctl_fd, ctl_hello, 37);
                    write(ctl_fd, ctl_hellow_answer, 1);
                    read(ctl_fd, &ctl_info_size, 4);

                    uint32_t isize = ntohl(ctl_info_size);
                    ctl_info = (uint8_t*)malloc(isize * sizeof(uint8_t));
                    read(ctl_fd, ctl_info, isize);
                    write(ctl_fd, ctl_info_answer, 1);

                    pthread_create(&tid, NULL, ctl_runner, (void*)&ctl_fd);

                    free(ctl_info);

                    break;

                } else {

                    read(client_fd, hello, 37);
                    connections += 1;

                    if(connections == client_num){
                        write(ctl_fd, ctl_start_1, 1);
                        write(ctl_fd, ctl_start_2, 1);
                    }

                }
                if(client_fd < 0){
                    printf("failed to accept\n");
                    break;
                }
                if(make_socket_non_blocking(client_fd) < 0){
                    printf("accept non-blocking failed\n");
                    break;
                }
                for(int i = 0; i < client_num; i++){
                    if(client_fds[i] == 0){
                        client_fds[i] = client_fd;
                        added = 1;
                        break;
                    }
                }
                if(added != 1){
                    printf("accept slot full\n");
                    break;
                }

            }
        } while(0);

        for(int i = 0; i < client_num; i++){
            if(event == 0){
                break;
            }
            client_fd = client_fds[i];
            if(client_fd == 0){
                continue;
            }
            if(FD_ISSET(client_fd, &readfds)){
                valread = 0;
                n = 0;
                while(valread < MAXBUFFLEN){
                    n = read(client_fd, client_buff[i] + valread, MAXBUFFLEN - valread);
                    if(n <= 0 && errno != EAGAIN){
                        client_fds[i] = 0;
                        break;
                    } else {

                        break;
                    }
                    valread += n;
                }
                
            }
            event -= 1;
        }

    }

    return 0;
}


int run_poll(int fd, struct sockaddr_in* servaddr){



    return 0;
}


int run_epoll(int fd, struct sockaddr_in* servaddr){


    return 0;
}