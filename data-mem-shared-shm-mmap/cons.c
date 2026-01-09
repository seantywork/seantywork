#include "mem-shared.h"


int main(){
 

    int shm_fd;

    void* ptr;

    char read_frame[FRAME_SIZE] = {0};

    shm_fd = shm_open(SHM_NAME, O_RDONLY, 0666);
 
    ptr = mmap(0, BLOCK_SIZE * FRAME_SIZE, PROT_READ, MAP_SHARED, shm_fd, 0);
 
    memcpy(read_frame, ptr, FRAME_SIZE);

    printf("%s ", read_frame);

    memset(read_frame, 0, FRAME_SIZE);
    
    ptr += FRAME_SIZE;

    memcpy(read_frame, ptr, FRAME_SIZE);

    printf("%s\n", read_frame);

    shm_unlink(SHM_NAME);
    
    printf("%s unlinked\n", SHM_NAME);

    return 0;
}