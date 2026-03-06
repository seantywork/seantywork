#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <stdatomic.h>

#define RELAX_CGROUP "gottarelax"
#define MAX_US 200000
#define PER_US 1000000
#define CPU_MAX_LEN 64


static int waitdone = 0;
void sig_usr1_hdl(int sig){
    if (sig == SIGUSR1){
        waitdone = 1;
    }
}

int main(){
    char carryon[8] = {0};
    char cpu_max[CPU_MAX_LEN] = {0};
    int status = 0;
    FILE* fp = NULL;
	int pid = fork();
    if(pid < 0){
        printf("failed to create child\n");
        return -1;
    }else if (pid == 0) {
        signal(SIGUSR1,sig_usr1_hdl);
        while(1){
            if(waitdone){
                break;
            }
            usleep(1);
        }
		execve("busy.out", NULL, NULL);
	} else {
        printf("child process is: %d\n", pid);
        mkdir("/sys/fs/cgroup/" RELAX_CGROUP, 0755);
        printf("created cgroup: %s\n", RELAX_CGROUP);
        printf("start the busy process: [ENTER]");
        fgets(carryon, 8, stdin);
        printf("\n");
        kill(pid, SIGUSR1);
        printf("limit process cpu use: [ENTER]");
        fgets(carryon, 8, stdin);
        printf("\n");
        fp = fopen("/sys/fs/cgroup/" RELAX_CGROUP "/cpu.max" , "w");
        if(fp == NULL){
            printf("failed to open file for group creation\n");
            return -1;
        }
        snprintf(cpu_max, CPU_MAX_LEN, "%d %d", MAX_US, PER_US);
        fwrite(cpu_max, sizeof(uint8_t), CPU_MAX_LEN, fp);
        fclose(fp);
        memset(cpu_max, 0, CPU_MAX_LEN);
        fp = fopen("/sys/fs/cgroup/" RELAX_CGROUP "/cgroup.procs" , "a");
        if(fp == NULL){
            printf("failed to open file for cpu limit\n");
            return -1;
        }
        snprintf(cpu_max, CPU_MAX_LEN, "%d", pid);
        fwrite(cpu_max, sizeof(uint8_t), CPU_MAX_LEN, fp);
        fclose(fp);
        printf("waiting for the child to end...\n");
        waitpid(pid, &status, 0);
        printf("========== parent process ==========\n");
        printf("done!\n");
        rmdir("/sys/fs/cgroup/" RELAX_CGROUP);
    }

    return 0;
}