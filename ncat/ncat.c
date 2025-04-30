#include "ncat.h"



void NCAT_keyboard_interrupt(){

    fprintf(stderr,"SIGINT. EXIT.\n");

    exit(0);

}


int NCAT_parse_args(int argc, char** argv){


    if(argc < 2){

        printf("needs argument: [-l|--listen] host port\n");

        return -1;
    }


    int argc_nohp = argc - 2;


    for(int i = 0 ; i < argc_nohp; i ++){


        if(
            (strcmp(argv[i], "--listen") == 0)
            || (strcmp(argv[i], "-l") == 0)
        ){

            ncat_opts.mode_listen = 1;

        }


    }

    if(ncat_opts.mode_listen == 0){
        ncat_opts.mode_client = 1;
    }


    int host_idx = argc_nohp;
    int port_idx = argc_nohp + 1;


    ncat_opts.host = argv[host_idx];
    ncat_opts.port = argv[port_idx];




    return 0;
}



void NCAT_free(){

    if(serve_content != NULL){

        free(serve_content);
    }

}


int NCAT_runner(){

    int status = 0;

    pthread_t thread_id;

    int flags_org = 0;

    if(ncat_opts.mode_listen == 1){

        int flags = 0;

        if(pipe(ncat_opts._server_sig) != 0){

            printf("failed to initiate server sig\n");

            return -1;

        }

        flags |= O_NONBLOCK;

        if (fcntl(ncat_opts._server_sig[0], F_SETFL, flags) != 0){

            printf("failed to setup server sig\n");

            return -2;
        }

        flags_org = fcntl(STDIN_FILENO,F_GETFL,0);

        if (fcntl(STDIN_FILENO, F_SETFL, flags) != 0){

            printf("failed to setup server stdin\n");

            return -3;
        }

    }


    pthread_create(&thread_id, NULL, NCAT_get_thread, NULL);

    if(ncat_opts.mode_client == 1){

        status = NCAT_client();

        return status;

    }

    if(ncat_opts.mode_listen == 1){

        struct pollfd sig_wait = {.fd = ncat_opts._server_sig[0], .events = POLLIN};

        char sig_result[SERVER_SIG_LEN] = {0};    

        for(int count = 0; count < SERVER_SIG_TIMEOUT_COUNT; count++){

            switch(poll(&sig_wait, 1, SERVER_SIG_TIMEOUT_MS)){

                case 1:
                    if (sig_wait.revents & POLLIN) {
  
                        ssize_t len = read(ncat_opts._server_sig[0], sig_result, SERVER_SIG_LEN);
    
                        count += SERVER_SIG_TIMEOUT_COUNT;

                        break;
                    }

                    break;
                default:

                    count += 1;

            }

        }

        if(strncmp(SERVER_SIG_DONE, sig_result, SERVER_SIG_LEN) != 0){

            if(serve_content != NULL){

                free(serve_content);
                serve_content = NULL;
            }
        } 

        close(ncat_opts._server_sig[0]);

        if (fcntl(STDIN_FILENO, F_SETFL, flags_org) != 0){

            printf("failed to setup server stdin to original\n");

            return -3;
        }

        status = NCAT_listen_and_serve();


        return status;

    } 


    fprintf(stderr, "unsupported mode\n");

    return -10;

}



int NCAT_client(){

    int result = 0;

    int sockfd = -1;
    struct sockaddr_in servaddr;
    in_addr_t s_addr = inet_addr(ncat_opts.host);
    int addr_port = atoi(ncat_opts.port);
    int keepalive = 1;
    NCAT_COMMS comms; 
    int chunk = 0;
    int content_len = 0;
    int message_len = 0;

    pthread_mutex_t stdlock;

    pthread_mutex_init(&stdlock, NULL);

    int header_size = sizeof(uint32_t);

    memset(&comms, 0, sizeof(comms));


    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        fprintf(stderr, "socket creation failed\n");
        result = -1;
        goto cli_out;
    }
 
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = s_addr;
    servaddr.sin_port = htons(addr_port);

    if (connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr))!= 0) {
        fprintf(stderr, "connection failed\n");
        result = -1;
        goto cli_out;
    }

    ncat_opts._client_sockfd = sockfd;
    ncat_opts._client_sock_ready = 1;

    //uint8_t data_static[4 + INPUT_BUFF_CHUNK] = {0};

    while(keepalive){

        content_len = header_size + 0;

        comms.data = (uint8_t*)malloc(header_size + (INPUT_BUFF_CHUNK));

//      comms.data = data_static;

        memset(comms.data, 0, header_size + (INPUT_BUFF_CHUNK));

        pthread_mutex_lock(&stdlock);

        fgets(comms.data + header_size, INPUT_BUFF_CHUNK - header_size, stdin);

        pthread_mutex_unlock(&stdlock);

        message_len = strlen(comms.data + header_size);

        content_len += message_len - 1;

        comms.data[content_len] = 0;

        comms.data = (uint8_t*)realloc(comms.data, content_len);

        if(strcmp(CLIENT_EXIT, (char*)(comms.data + header_size)) == 0){

            keepalive = 0;
//            comms.data = NULL;
            continue;
        }


        comms.datalen = htonl(content_len - header_size);
        memcpy(comms.data, &comms.datalen, header_size);

        int wb = write(sockfd, comms.data, content_len);

        if(wb <= 0){

            keepalive = 0;
            continue;
        }

        free(comms.data);


    }   

    ncat_opts._client_sock_ready = 0;

cli_out:

    if(sockfd != -1){

        close(sockfd);
    }

    if(comms.data != NULL){

        free(comms.data);
    }

 
    return result;
}


int NCAT_listen_and_serve(){
    
    int result = 0;
    int sockfd, connfd = -1; 
    struct sockaddr_in servaddr, cli; 

    in_addr_t s_addr = inet_addr(ncat_opts.host);
    
    int addr_port = atoi(ncat_opts.port);

    int enable = 1;
        
    int clilen = sizeof(cli); 

    NCAT_COMMS comms;

    memset(&comms, 0, sizeof(comms));



    sockfd = socket(AF_INET, SOCK_STREAM, 0); 
    if (sockfd == -1) { 
        fprintf(stderr,"socket creation failed...\n"); 
        result = -1;
        goto srv_out;
    } 

    servaddr.sin_family = AF_INET; 
    servaddr.sin_addr.s_addr = s_addr; 
    servaddr.sin_port = htons(addr_port); 
   
    if ((bind(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr))) != 0) { 
        fprintf(stderr, "socket bind failed\n"); 
        result = -1;
        goto srv_out;
    } 
   

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0){
        fprintf(stderr, "socket opt failed\n"); 
        result = -1;
        goto srv_out; 
    }

    if ((listen(sockfd, 1)) != 0) { 
        fprintf(stderr,"socket listen failed\n"); 
        result = -1;
        goto srv_out;
    } 
    

    while(_exit_prog != 1){


        connfd = accept(sockfd, (struct sockaddr*)&cli, (socklen_t*)&clilen); 
        if (connfd < 0) { 
            fprintf(stderr, "server accept failed\n"); 
            continue;
        } 
    
        
        int valwrite =0;

        if(serve_content != NULL){

            uint32_t contentlen = strlen(serve_content);

            comms.datalen = htonl(contentlen);
            comms.data = (uint8_t*)malloc(sizeof(uint32_t) + contentlen);

            memcpy(comms.data, &comms.datalen, sizeof(uint32_t));
            memcpy(comms.data + sizeof(uint32_t), serve_content, contentlen);

            valwrite = write(connfd, comms.data, sizeof(uint32_t) + contentlen);

            if(valwrite <= 0){

                fprintf(stderr,"write: %d\n", valwrite);

            }


            free(comms.data);
        }

        int keepalive = 1;

        comms.datalen = 0;
        comms.data = NULL;
        uint32_t rhead = 0;

        while(keepalive){


            int valread = 0;

            while(valread < sizeof(uint32_t)){

                int rb = read(connfd, &rhead + valread, sizeof(uint32_t) - valread);


                if (rb <= 0){

                    keepalive = 0;
                    break;

                } 

                valread += rb;

            }

            if(keepalive == 0){
                continue;
            }

            comms.datalen = ntohl(rhead);

            comms.data = (uint8_t*)malloc(comms.datalen + 1);

            comms.data[comms.datalen] = 0;

            valread = 0;


            while(valread < comms.datalen){

                int rb = read(connfd, comms.data + valread, comms.datalen - valread);

                if (rb <= 0){

                    keepalive = 0;
                    break;

                } 

                valread += rb;

            }

            if(keepalive == 0){
                continue;
            }
            fprintf(stdout, "%s\n", comms.data);

            free(comms.data);

        }

        close(connfd);

    }

srv_out:

    if(sockfd < -1){

        close(sockfd);
    }

    if(comms.data != NULL){

        free(comms.data);
    }


    return 0;
}



void* NCAT_get_thread(){

    if(ncat_opts.mode_client){

        NCAT_COMMS comms;

        memset(&comms, 0, sizeof(NCAT_COMMS));

        int _exit_prog = 0;

        while(_exit_prog != 1){

            if(ncat_opts._client_sock_ready){

                int valread = 0;

                uint32_t rhead = 0;
                
                while(valread < sizeof(uint32_t)){

                    int rb = read(ncat_opts._client_sockfd, &rhead + valread, sizeof(uint32_t) - valread);

                    if(rb <= 0){
                        
                        _exit_prog = 1;

                        break;

                    }

                    valread += rb;
                }

                if(_exit_prog == 1){

                    continue;
                }
               
                comms.datalen = ntohl(rhead);

                comms.data = (uint8_t*)malloc(comms.datalen);

                valread = 0;

                while(valread < comms.datalen){

                    int rb = read(ncat_opts._client_sockfd, comms.data + valread, comms.datalen - valread);

                    if(rb <= 0){
                        
                        _exit_prog = 1;

                        break;

                    }

                    valread += rb;
                }

                if(_exit_prog == 1){

                   free(comms.data);   

                    continue;
                }

                fprintf(stdout, "%s\n", comms.data);

                free(comms.data);
                

            } else {
                
                msleep(100);

            }


        }


    } else if (ncat_opts.mode_listen){

        struct pollfd sig_wait = {.fd = STDIN_FILENO, .events = POLLIN};

        int chunk = 1;

        int content_len = 0;

        serve_content = (char*)malloc(INPUT_BUFF_CHUNK * chunk);

        memset(serve_content, 0, INPUT_BUFF_CHUNK * chunk);

        char* content_ptr = serve_content + content_len;

        char c = 0;

        for(int count = 0; count < 1; count++){

            switch(poll(&sig_wait, 1, SERVER_SIG_TIMEOUT_MS)){

                case 1:
                    
                    while((c = fgetc(stdin)) != EOF){


                        *content_ptr = c; 
            
                        content_len += 1;
            
                        if(content_len == (INPUT_BUFF_CHUNK * chunk)){
            
                            chunk += 1;
            
                            serve_content = (char*)realloc(serve_content, INPUT_BUFF_CHUNK * chunk);
            
                        }
            
                        content_ptr = serve_content + content_len;
                        
                    }
        
                default:

                    count += 1;

            }

        }

        if(content_len != 0){
            printf("loaded server text: \n%s\n", serve_content);
            write(ncat_opts._server_sig[1], SERVER_SIG_DONE, SERVER_SIG_LEN);
        }


    }

    pthread_exit(NULL);

}


void msleep(long ms){

    struct timespec ts;

    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000;

    nanosleep(&ts, &ts);
}