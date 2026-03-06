#include "mem-shared.h"


int main(){
 
 
    
    const char* message_0 = "producer message";
    const char* message_1 = "> hello consumer";

    char write_frame[FRAME_SIZE] = {0};

    int shm_fd;
 
    void* ptr;
 
    shm_fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0666);
 
    ftruncate(shm_fd, BLOCK_SIZE * FRAME_SIZE);
    ptr = mmap(0, BLOCK_SIZE * FRAME_SIZE, PROT_WRITE, MAP_SHARED, shm_fd, 0);

    printf("%s created\n", SHM_NAME);

    strcpy(write_frame, message_0);

    int prod = sprintf(ptr, "%s", write_frame);
 
    ptr += FRAME_SIZE;

    memset(write_frame, 0 , FRAME_SIZE);

    strcpy(write_frame, message_1);

    prod = sprintf(ptr, "%s", write_frame);
    
    ptr += FRAME_SIZE;

    printf("message posted\n");
    
    return 0;
}