#include "tenk.h"



void* run_client_thread(void* varg){

    int tid = *(int*)varg;

    int fdstart = tid * CLIENTS_PER_THREAD;

    int fdend = tid + CLIENTS_PER_THREAD;

    int count = 0;
    
    int n = 0;

    while(count < THREAD_ITER){

        if(getrandom(wbuff[tid], MAXBUFFLEN, 0) < 0){

            printf("getrandom failed\n");

            continue;
        }

        for(int i = fdstart; i < fdend; i++){

            n = write(wfds[i], wbuff[tid], MAXBUFFLEN);

            if(n <= 0){

                printf("failed to write: %d\n", i);

                continue;

            }

        }

        count += 1;

    }

    wdones[tid] = 1;

    pthread_exit(NULL);

}



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


int run_select(int fd, struct sockaddr_in* servaddr){

    printf("server mode: select\n");

    int connections = 0;
    int connections_printed = 0;

    int max_fd = 0;
    int event = 0;
    fd_set readfds;
    int servlen;
    int client_fds[MAXCLIENT] = {0};
    int valread;
    int n;
    int client_fd;

    int keep = 1;

    servlen = sizeof(*servaddr);   
    
    while(keep){

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

                if(client_fd < 0){

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

                connections += 1;

            }
        } while(0);

        if(connections != MAXCLIENT){

            continue;
        } else {

            if(connections_printed == 0){

                printf("connection reached: %d\n", connections);
                connections_printed = 1;
            }
        }

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
                    if(n < 0 && errno != EAGAIN){

                        printf("fatal\n");

                        keep = 0;
                        break;
                    } else if (n < 0 && errno == EAGAIN){

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

    printf("server mode: poll\n");


    int connections = 0;
    int connections_printed = 0;

    int event = 0;
    struct pollfd* pollfds = NULL;
    int servlen;
    int valread;
    int n;
    int client_fd;

    int idx;

    int keep = 1;

    servlen = sizeof(*servaddr);   

    pollfds = (struct pollfd*)malloc((client_num + 1) * sizeof(struct pollfd));

    memset(pollfds, 0, (client_num + 1) * sizeof(struct pollfd));

    pollfds[0].fd = fd;
    pollfds[0].events = POLLIN;

    for(int i = 1; i < client_num + 1; i++){

        pollfds[i].fd = 0;
        pollfds[i].events = POLLIN;

    }

    while(keep){

        event = poll(pollfds, client_num + 1, -1);


        do {

            if(pollfds[0].revents & POLLIN){

                int added = 0;

                event -= 1;

                client_fd = accept(fd, (struct sockaddr*)servaddr, (socklen_t*)&servlen);
                if(client_fd < 0){

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

                connections += 1;

            }

        } while(0);

        if(connections != MAXCLIENT){

            continue;
        } else {

            if(connections_printed == 0){

                printf("connection reached: %d\n", connections);
                connections_printed = 1;
            }
        }


        for(int i = 1; i < client_num + 1; i++){

            idx = i - 1;

            if(event == 0){
                break;
            }
            
            if(pollfds[i].fd == 0){
                continue;
            }

            if(pollfds[i].revents & POLLIN){

                valread = 0;
                n = 0;
                event -= 1;
                while(valread < MAXBUFFLEN){
                    n = read(pollfds[i].fd, client_buff[idx] + valread, MAXBUFFLEN - valread);
                    if(n < 0 && errno != EAGAIN){

                        printf("fatal\n");

                        keep = 0;
                        break;
                    } else if (n < 0 && errno == EAGAIN){

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

static inline int epoll_add_idx(int* client_fds, int fd){

    int done = 0;
    int idx = fd % MAXCLIENT;
    int start_idx = idx;

    while(done == 0){

        if(client_fds[idx] == 0){

            client_fds[idx] = fd;

            done = idx;

            break;
        } else {
            idx += 1;
        }

        if(idx == MAXCLIENT){
            idx = 0;
        }

        if(idx == start_idx){
            done = -1;
        }

    }

    return done;
}

static inline int epoll_get_idx(int* client_fds, int fd){

    int done = 0;
    int idx = fd % MAXCLIENT;
    int start_idx = idx;

    while(done == 0){

        if(client_fds[idx] == fd){

            done = idx;

            break;
        } else {
            idx += 1;
        }

        if(idx == MAXCLIENT){
            idx = 0;
        }

        if(idx == start_idx){
            done = -1;
        }

    }

    return done;
}

int run_epoll(int fd, struct sockaddr_in* servaddr){

    printf("server mode: epoll\n");


    int connections = 0;
    int connections_printed = 0;

    int event;
    struct epoll_event ev; 
    struct epoll_event* evs = NULL;
    int servlen;
    int valread;
    int n;
    int client_fd;

    int client_fds[MAXCLIENT] = {0};

    int idx;

    int keep = 1;

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
    ev.events = EPOLLIN;

    if(epoll_ctl(eplfd, EPOLL_CTL_ADD, fd, &ev) < 0){
        printf("epoll add failed\n");
        return -1;
    }

    while(keep){

        event = epoll_wait(eplfd, evs, client_num + 1, -1);

        for(int i = 0 ; i < event; i++){

            if (
                evs[i].events & EPOLLHUP ||
                evs[i].events & EPOLLERR ||
                (!(evs[i].events & EPOLLIN))
            ){
                continue;
            }

            if(evs[i].data.fd == fd){

                int added = 0;

                client_fd = accept(fd, (struct sockaddr*)servaddr, (socklen_t*)&servlen);
                if(client_fd < 0){

                    continue;
                }


                if(make_socket_non_blocking(client_fd) < 0){
                    printf("accept non-blocking failed\n");
                    continue;
                }


                ev.data.fd = client_fd;
                ev.events = EPOLLIN ;

                if(epoll_ctl(eplfd, EPOLL_CTL_ADD, client_fd, &ev) < 0){
                    printf("epoll add client failed\n");
                    continue;
                }

                idx = epoll_add_idx(client_fds, client_fd);

                if(idx < 0){
                    printf("epoll add slot full\n");
                    continue;
                }

                connections += 1;

            } else {

                if(connections != MAXCLIENT){

                    continue;
                } else {
        
                    if(connections_printed == 0){
        
                        printf("connection reached: %d\n", connections);
                        connections_printed = 1;
                    }
                }
        
                idx = epoll_get_idx(client_fds, evs[i].data.fd);

                if(idx < 0){
                    printf("epoll get slot failed\n");
                    continue;
                }

                valread = 0;
                n = 0;
                while(valread < MAXBUFFLEN){
                    n = read(evs[i].data.fd, client_buff[idx] + valread, MAXBUFFLEN - valread);
                    if(n < 0 && errno != EAGAIN){

                        printf("fatal\n");

                        keep = 0;
                        break;
                    } else if (n < 0 && errno == EAGAIN){

                        break;
                    }
                    valread += n;
                }

            }

        }

    }

epoll_out:

    free(evs);

    return 0;
}