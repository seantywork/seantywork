# cgroup

- [code](https://github.com/seantywork/seantywork/tree/main/data-cgroup)

On Linux host, we can utilize a thing called `cgroup` (to be specific `cgroup_v2`) to \
manage how much resource a process is allowed to have while running. For example, we \
can control how much CPU time a process is allowed to have per second.

There are more than one way to do this, but today we are going to look at how to \
directly deal with `sysfs` to have a process work under cgroup.

If we take a look at the directory, we'll see that there are two files available for compilation.

```shell
$ make
gcc -g -o test.out main.c 
gcc -g -o busy.out busy.c 

```
One program is called `busy.out` and the other `test.out`.

`busy.out` is a simple program that does a busy-looping for a finite number of times \
and then exits. If we run this we'll know there is nothing much going on except for \
hogging cpu.

```shell
$ time ./busy.out 
[CUT]
running: 99995
running: 99996
running: 99997
running: 99998
running: 99999
extremely busy process is completed

real    0m2.848s
user    0m0.155s
sys     0m2.340s
```
There is no sign at all that this program is NOT using the 100% of CPU. We'll be more \
clearly able to see it using `htop` if we adjust the `HOWMANY` in `busy.c` higher up \
and make it run for longer.

Now let's take a look at our `test.out` program.

```c
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
```

It forks a child process, and the child process wait for `SIGUSR1` signal \
before executing out `busy.out` program...

```c
	} else {
        printf("child process is: %d\n", pid);
        // here, this syscall will create cgroup subgroup...
        mkdir("/sys/fs/cgroup/" RELAX_CGROUP, 0755);
        printf("created cgroup: %s\n", RELAX_CGROUP);
        // waiting for user ENTER...
        printf("start the busy process: [ENTER]");
        fgets(carryon, 8, stdin);
        printf("\n");
        // if user hits ENTER, the child process will fire up
        kill(pid, SIGUSR1);

```
And then, as we can see, the parent process proceeds to create entry under \
`/sys/fs/cgroup/` named `RELAX_CGROUP`. If user hits enter, the child process \
will immediately start.

After this awaits the moment where we can put the constraint on the \
very busy child process. As you can see below.

```c
        // if user hits ENTER again...
        printf("limit process cpu use: [ENTER]");
        fgets(carryon, 8, stdin);
        printf("\n");
        // this process will open file for cpu max usage constraint...
        fp = fopen("/sys/fs/cgroup/" RELAX_CGROUP "/cpu.max" , "w");
        if(fp == NULL){
            printf("failed to open file for group creation\n");
            return -1;
        }
        snprintf(cpu_max, CPU_MAX_LEN, "%d %d", MAX_US, PER_US);
        // and then set the details for the constraint, 
        // such as, $MAX_US micro second in $PER_US micro second
        fwrite(cpu_max, sizeof(uint8_t), CPU_MAX_LEN, fp);
        fclose(fp);
        memset(cpu_max, 0, CPU_MAX_LEN);
        // then, finally, register the $pid to the file below
        // to make the constraint go into effect on the $pid
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

```

We'll see that immediately after registering the child process id to \
the newly created cgroup, the busy process slows down drastically.

```shell
$ sudo time ./test.out 
[sudo] password for thy: 
child process is: 631469
created cgroup: gottarelax
start the busy process: [ENTER]
# hits enter in the middle of busy process output
[CUT]
# slowed enough to copy the output
running: 61138
running: 61139
running: 61140
running: 61141
running: 61142
running: 61143
running: 61144
running: 61145
running: 61146
running: 61147
running: 61148
running: 61149
running: 61150
running: 61151
running: 61152
[CUT]
extremely busy process is completed
========== parent process ==========
done!
```

Below section contains some commands related to `cgroup`


# misc

```shell

# check cgroup mount location
mount | grep cgroup2

# if nnone, change kernel parameters in grub to see
# cgroup_no_v1=all
cat /proc/cmdline

# check controllers
cat /sys/fs/cgroup/cgroup.controllers

# add controller , here SOMETHING being cpu 
echo "+$SOMETHING" >> /sys/fs/cgroup/cgroup.subtree_control  

# add sub group
mkdir /sys/fs/cgroup/$SOME_GROUP

# give cpu max
MAX_US=200000
PER_US=1000000

echo "$MAX_US $PER_US" > /sys/fs/cgroup/$SOME_GROUP/cpu.max
echo "$PID" > /sys/fs/cgroup/$SOME_GROUP/cgroup.procs

# revoke group
rmdir /sys/fs/cgroup/$SOME_GROUP


```