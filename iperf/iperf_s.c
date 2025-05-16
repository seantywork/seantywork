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

void* ctl_thread(void* varg){

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

    pthread_exit(NULL);

}

void ctl_runner(){

    pthread_t tid;

    read(ctl_fd, ctl_hello, 37);
    write(ctl_fd, ctl_hellow_answer, 1);
    read(ctl_fd, &ctl_info_size, 4);

    uint32_t isize = ntohl(ctl_info_size);
    ctl_info = (uint8_t*)malloc(isize * sizeof(uint8_t));
    read(ctl_fd, ctl_info, isize);
    write(ctl_fd, ctl_info_answer, 1);

    pthread_create(&tid, NULL, ctl_thread, NULL);

    free(ctl_info);

}

int run_select(int fd, struct sockaddr_in* servaddr){

    int connections = 0;

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
                event -= 1;
                client_fd = accept(fd, (struct sockaddr*)servaddr, (socklen_t*)&servlen);

                if(ctl_fd == 0){

                    ctl_fd = client_fd;

                    ctl_runner(ctl_fd);

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
                event -= 1;
                while(valread < MAXBUFFLEN){
                    n = read(client_fd, client_buff[i] + valread, MAXBUFFLEN - valread);
                    if(n <= 0 && errno != EAGAIN){
                        client_fds[i] = 0;
                        break;
                    } 
                    valread += n;
                }
                
            }
        }

    }

    return 0;
}


int run_poll(int fd, struct sockaddr_in* servaddr){


    int connections = 0;

    int event = 0;
    struct pollfd* pollfds = NULL;
    int servlen;
    int valread;
    int n;
    int client_fd;

    servlen = sizeof(*servaddr);   

    pollfds = (struct pollfd*)malloc((client_num + 1) * sizeof(struct pollfd));

    memset(pollfds, 0, (client_num + 1) * sizeof(struct pollfd));

    pollfds[0].fd = fd;
    pollfds[0].events = POLLIN | POLLPRI;

    for(int i = 1; i < client_num + 1; i++){

        pollfds[i].fd = 0;
        pollfds[i].events = POLLIN | POLLPRI;

    }

    while(1){

        event = poll(pollfds, client_num + 1, -1);

        if ((event < 0 ) && (errno != EINTR)){
            printf("poll error\n");
            break;
        }

        do {

            if(pollfds[0].revents & POLLIN){

                int added = 0;

                event -= 1;

                client_fd = accept(fd, (struct sockaddr*)servaddr, (socklen_t*)&servlen);

                if(ctl_fd == 0){

                    ctl_fd = client_fd;

                    ctl_runner(ctl_fd);

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

                for(int i = 1; i < client_num + 1; i++){
                    if(pollfds[i].fd == 0){
                        pollfds[i].fd = client_fd;
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

        for(int i = 1; i < client_num + 1; i++){

            if(event == 0){
                break;
            }
            client_fd = pollfds[i].fd;
            if(client_fd == 0){
                continue;
            }

            if(pollfds[i].revents & POLLIN){

                valread = 0;
                n = 0;
                event -= 1;
                while(valread < MAXBUFFLEN){
                    n = read(client_fd, client_buff[i] + valread, MAXBUFFLEN - valread);
                    if(n <= 0 && errno != EAGAIN){
                        pollfds[i].fd = 0;
                        break;
                    } else {

                        break;
                    }
                    valread += n;
                }

            }

        }

    }

poll_out:

    free(pollfds);

    return 0;
}


int run_epoll(int fd, struct sockaddr_in* servaddr){

    int connections = 0;

    struct epoll_event ev; 
    struct epoll_event* evs = NULL;
    int servlen;
    int valread;
    int n;
    int client_fd;

    int eplfd = 0;

    servlen = sizeof(*servaddr);   

    eplfd = epoll_create1(0);

    if(eplfd == -1){
        printf("failed to create epoll fd\n");
        return -1;
    }

    evs = (struct epoll_event*)malloc((client_num + 1) * sizeof(struct epoll_event));

    memset(evs, 0, (client_num + 1) * sizeof(struct epoll_event));

    ev.data.fd = fd;
    ev.events = EPOLLIN | EPOLLET;

    if(epoll_ctl(eplfd, EPOLL_CTL_ADD, fd, &ev) < 0){
        printf("epoll add failed\n");
        return -1;
    }

    while(1){


        event = epoll_wait(eplfd, evs, client_num + 1, -1);

        for(int i = 0 ; i < event; i++){

            if(evs[i].events & EPOLLIN){

                if(evs[i].data.fd == fd){

                    int added = 0;
    
                    client_fd = accept(fd, (struct sockaddr*)servaddr, (socklen_t*)&servlen);
    
                    if(ctl_fd == 0){
    
                        ctl_fd = client_fd;
    
                        ctl_runner(ctl_fd);
    
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
    
                    for(int i = 1; i < client_num + 1; i++){
                        if(pollfds[i].fd == 0){
                            pollfds[i].fd = client_fd;
                            added = 1;
                            break;
                        }
                    }
                    if(added != 1){
                        printf("accept slot full\n");
                        break;
                    }



                } else {






                }


            }

        }

    }

    free(evs);

    return 0;
}