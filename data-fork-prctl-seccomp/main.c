#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/seccomp.h>

#include <fcntl.h>
#include <sys/wait.h>
#include <stdlib.h>


int main(void)
{
    int status;

    /* spawn child process, connected by a pipe */
    pid_t w;
    pid_t pid = fork();
    if (pid == 0) {

        /* enter mode 1 seccomp and execute untrusted bytecode */
        prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);

        /* send result over pipe, and exit */
        int input = open("test.txt", O_RDONLY | O_WRONLY);

        sleep(10);
        syscall(SYS_exit, 0);
    } else {

        do {
            w = waitpid(pid, &status, 0);
            if (w == -1) {
                perror("waitpid");
                exit(EXIT_FAILURE);
            }

           if (WIFEXITED(status)) {
                printf("exited, status=%d\n", WEXITSTATUS(status));
            } else if (WIFSIGNALED(status)) {
                printf("killed by signal %d\n", WTERMSIG(status));
            } else if (WIFSTOPPED(status)) {
                printf("stopped by signal %d\n", WSTOPSIG(status));
            } else if (WIFCONTINUED(status)) {
                printf("continued\n");
            }
        } while (!WIFEXITED(status) && !WIFSIGNALED(status));
        exit(EXIT_SUCCESS);
    }
}