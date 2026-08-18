package cpu

import (
	"runtime"
)

/*
#define _GNU_SOURCE
#include <sched.h>
#include <pthread.h>
void lock_thread(int cpuid) {
        pthread_t tid;
        cpu_set_t cpuset;
        tid = pthread_self();
        CPU_ZERO(&cpuset);
        CPU_SET(cpuid, &cpuset);
    pthread_setaffinity_np(tid, sizeof(cpu_set_t), &cpuset);
}
*/
import "C"

func SetThreadCPUAffinity(cpuID int) {
	runtime.LockOSThread()
	C.lock_thread(C.int(cpuID))
}
