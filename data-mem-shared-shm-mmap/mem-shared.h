#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <string.h>
#include <unistd.h>

#define BLOCK_SIZE 4096
#define FRAME_SIZE 2048
#define SHM_NAME "SHMADDR_prodcons_test"
