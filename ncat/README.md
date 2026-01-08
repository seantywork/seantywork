
# 01

```shell
$ gcc --version
gcc (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0
Copyright (C) 2023 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.  There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
```


# 02

```shell
$ cargo --version
cargo 1.86.0 (adf9b6ad1 2025-02-28)
```

# 03

```shell
$ uname -a
Linux ubuntu24-8 6.8.0-58-generic #60-Ubuntu SMP PREEMPT_DYNAMIC Fri Mar 14 18:29:48 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
```

# 04 

```shell
$ nc -l 0.0.0.0 9999

```

# 05 

```shell

$ nc 0.0.0.0 9999

```


# 06

```shell
$ nc 0.0.0.0 9999
asdfqwer

$ nc -l 0.0.0.0 9999
asdfqwer
```

# 07

```shell

$ nc -l 0.0.0.0 9999 < test.http 
 

$ nc 0.0.0.0 9999
HTTP/1.0 200 OK

<html>
  <body>
    <h1>Hello, world!</h1>
  </body>
</html>
```

# 08

```shell
ncat$ make
```

# 09

```shell
GCC_FLAGS := -Wall -O2 -static


all: ncat.o

	gcc $(GCC_FLAGS) -I. -o ncat.out main.c ncat.o -lpthread


ncat.o: 

	gcc $(GCC_FLAGS) -c -I. -o ncat.o ncat.c

clean:
	rm -r *.o *.a *.so *.out

```

# 10

```shell
0xetc/0xrs/ncat$ ./build.sh
```

# 11

```shell
cargo build --release 

# For example, here are the default values for the opt-level setting for the dev and release profiles:
# ...
# [profile.release]
# opt-level = 3
# https://doc.rust-lang.org/book/ch14-01-release-profiles.html
```


# 12


```c

// data
// struct to hold global variables

typedef struct NCAT_OPTIONS {

    int mode_client;
    int mode_listen;
    int _client_sock_ready;
    int _client_sockfd;
    int _server_sig[2];
    char* host;
    char* port;

} NCAT_OPTIONS;

...

// the global variable struct

extern NCAT_OPTIONS ncat_opts;

...

// flow
// 01. register keyboard interrupt

void NCAT_keyboard_interrupt();

// 02. parse arguments and make it usable across the program

int NCAT_parse_args(int argc, char** argv);

// 03. free allocated memories

void NCAT_free();

// 04. create thread, decide whether to run client or server

int NCAT_runner();

// 05. client mode, read from stdin and send to server

int NCAT_client();

// 05. server mode, accept, read, and write to stdout

int NCAT_listen_and_serve();

// 06. in client mode, it reads server message and write to stdout,
//     in server mode, it reads from stdin and ready the buffer to serve
//     on new connection

void* NCAT_get_thread();



...

```




# 13

```shell


ncat$ ./test.sh 
creating interface...
creating 1000000 entries...
test.txt exists
running test...

 Performance counter stats for './ncat.out 192.168.62.6 9999':

          1,149.31 msec task-clock                       #    0.692 CPUs utilized             
                82      context-switches                 #   71.347 /sec                      
                 5      cpu-migrations                   #    4.350 /sec                      
                35      page-faults                      #   30.453 /sec                      
     4,915,902,430      cycles                           #    4.277 GHz                         (49.85%)
     3,736,492,322      instructions                     #    0.76  insn per cycle              (62.39%)
       696,645,936      branches                         #  606.144 M/sec                       (62.46%)
         4,626,299      branch-misses                    #    0.66% of all branches             (62.52%)
       945,180,544      L1-dcache-loads                  #  822.391 M/sec                       (62.65%)
        21,471,338      L1-dcache-load-misses            #    2.27% of all L1-dcache accesses   (62.65%)
         1,514,938      LLC-loads                        #    1.318 M/sec                       (50.03%)
           574,598      LLC-load-misses                  #   37.93% of all LL-cache accesses    (49.88%)

       1.660428866 seconds time elapsed

       0.573369000 seconds user
       0.576371000 seconds sys


test completed

```

# 14

```shell

0xetc/0xrs/ncat$ ./test.sh 
creating interface...
creating 1000000 entries...
test.txt exists
running test...

 Performance counter stats for './ncat.out 192.168.62.6 9999':

            989.07 msec task-clock                       #    0.445 CPUs utilized             
               177      context-switches                 #  178.955 /sec                      
                 4      cpu-migrations                   #    4.044 /sec                      
                91      page-faults                      #   92.005 /sec                      
     4,223,327,220      cycles                           #    4.270 GHz                         (49.90%)
     3,930,952,505      instructions                     #    0.93  insn per cycle              (62.49%)
       741,770,843      branches                         #  749.965 M/sec                       (62.53%)
         4,071,413      branch-misses                    #    0.55% of all branches             (62.51%)
       983,136,962      L1-dcache-loads                  #  993.997 M/sec                       (62.65%)
        11,295,559      L1-dcache-load-misses            #    1.15% of all L1-dcache accesses   (62.63%)
         1,445,219      LLC-loads                        #    1.461 M/sec                       (49.96%)
           570,018      LLC-load-misses                  #   39.44% of all LL-cache accesses    (49.96%)

       2.223086985 seconds time elapsed

       0.516193000 seconds user
       0.473260000 seconds sys


test completed

```


# 15

```c
/*

        TO SEE IF BOTTLENECK IS NETWORK IO

        comms.datalen = htonl(content_len - header_size);
        memcpy(comms.data, &comms.datalen, header_size);

        int wb = write(sockfd, comms.data, content_len);

        if(wb <= 0){

            keepalive = 0;
            continue;
        }
*/

```

```shell

creating interface...
creating 1000000 entries...
test.txt exists
running test...

 Performance counter stats for './ncat.out 192.168.62.6 9999':

            273.84 msec task-clock                       #    0.999 CPUs utilized             
                 8      context-switches                 #   29.214 /sec                      
                 0      cpu-migrations                   #    0.000 /sec                      
                35      page-faults                      #  127.812 /sec                      
     1,150,016,992      cycles                           #    4.200 GHz                         (49.80%)
     1,140,874,002      instructions                     #    0.99  insn per cycle              (62.58%)
       246,471,415      branches                         #  900.055 M/sec                       (62.76%)
           187,193      branch-misses                    #    0.08% of all branches             (62.76%)
       256,823,002      L1-dcache-loads                  #  937.856 M/sec                       (62.76%)
         1,466,330      L1-dcache-load-misses            #    0.57% of all L1-dcache accesses   (62.64%)
         1,088,490      LLC-loads                        #    3.975 M/sec                       (49.68%)
           560,838      LLC-load-misses                  #   51.52% of all LL-cache accesses    (49.68%)

       0.274222460 seconds time elapsed

       0.260067000 seconds user
       0.014003000 seconds sys


test completed


```

# 16

```rust

/*
        TO SEE IF BOTTLENECK IS NETWORK IO
        
        let mut header = [0u8; 4];

        let mut message_size = [0u32];

        message_size[0] = message.len() as u32;

        BigEndian::write_u32_into(&message_size, &mut header);

        let mut wbuff_vec = header.to_vec();

        let mut message_vec = message.as_bytes().to_vec();

        wbuff_vec.append(&mut message_vec);

        let wsize = io_stream.write(&wbuff_vec).unwrap();

        if wsize <= 0 {

            println!("failed to write: {}", wsize);
        }
*/

```


```shell

creating interface...
creating 1000000 entries...
test.txt exists
running test...

 Performance counter stats for './ncat.out 192.168.62.6 9999':

             77.45 msec task-clock                       #    0.997 CPUs utilized             
                 4      context-switches                 #   51.649 /sec                      
                 0      cpu-migrations                   #    0.000 /sec                      
                89      page-faults                      #    1.149 K/sec                     
       323,097,097      cycles                           #    4.172 GHz                         (48.18%)
       764,047,641      instructions                     #    2.36  insn per cycle              (61.26%)
       163,182,395      branches                         #    2.107 G/sec                       (61.55%)
           309,205      branch-misses                    #    0.19% of all branches             (62.84%)
       168,826,594      L1-dcache-loads                  #    2.180 G/sec                       (64.14%)
         1,486,727      L1-dcache-load-misses            #    0.88% of all L1-dcache accesses   (64.63%)
           996,921      LLC-loads                        #   12.872 M/sec                       (50.18%)
           499,547      LLC-load-misses                  #   50.11% of all LL-cache accesses    (48.96%)

       0.077660220 seconds time elapsed

       0.067662000 seconds user
       0.009950000 seconds sys


test completed



```



# 17

```c

    uint8_t data_static[4 + INPUT_BUFF_CHUNK] = {0};

    while(keepalive){

        content_len = header_size + 0;

//       comms.data = (uint8_t*)malloc(header_size + (INPUT_BUFF_CHUNK));

        comms.data = data_static;

        memset(comms.data, 0, header_size + (INPUT_BUFF_CHUNK));

        pthread_mutex_lock(&stdlock);

        fgets(comms.data + header_size, INPUT_BUFF_CHUNK - header_size, stdin);

        pthread_mutex_unlock(&stdlock);

        message_len = strlen(comms.data + header_size);

        content_len += message_len - 1;

        comms.data[content_len] = 0;

//        comms.data = (uint8_t*)realloc(comms.data, content_len);

        if(strcmp(CLIENT_EXIT, (char*)(comms.data + header_size)) == 0){

            keepalive = 0;
            comms.data = NULL;
            continue;
        }

/*
        comms.datalen = htonl(content_len - header_size);
        memcpy(comms.data, &comms.datalen, header_size);

        int wb = write(sockfd, comms.data, content_len);

        if(wb <= 0){

            keepalive = 0;
            continue;
        }
*/
//        free(comms.data);


    }   

```


```shell
ncat$ ./test.sh 
creating interface...
creating 1000000 entries...
test.txt exists
running test...

 Performance counter stats for './ncat.out 192.168.62.6 9999':

            143.93 msec task-clock                       #    0.997 CPUs utilized             
                 2      context-switches                 #   13.896 /sec                      
                 0      cpu-migrations                   #    0.000 /sec                      
                32      page-faults                      #  222.330 /sec                      
       541,504,050      cycles                           #    3.762 GHz                         (49.92%)
       392,731,304      instructions                     #    0.73  insn per cycle              (62.48%)
        85,665,835      branches                         #  595.189 M/sec                       (62.49%)
           156,129      branch-misses                    #    0.18% of all branches             (62.48%)
        91,212,527      L1-dcache-loads                  #  633.727 M/sec                       (62.48%)
         1,385,077      L1-dcache-load-misses            #    1.52% of all L1-dcache accesses   (62.63%)
           982,215      LLC-loads                        #    6.824 M/sec                       (50.06%)
           476,824      LLC-load-misses                  #   48.55% of all LL-cache accesses    (50.08%)

       0.144311729 seconds time elapsed

       0.128300000 seconds user
       0.016037000 seconds sys


test completed


```