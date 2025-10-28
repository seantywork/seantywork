# how to patch linux kernel? example using realtime patch for linux kernel 


```shell
$ sudo apt update
$ sudo apt install build-essential git libssl-dev libelf-dev flex bison debhelper-compat bc

```

```shell

$ uname -a
Linux ubuntu24-server 6.8.0-71-generic #71-Ubuntu SMP PREEMPT_DYNAMIC Tue Jul 22 16:52:38 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux


```


```shell
$ curl -L https://mirrors.edge.kernel.org/pub/linux/kernel/v6.x/linux-6.8.tar.gz -o linux-6.8.tar.gz

$ tar xzf linux-6.8.tar.gz
```

```shell
$ curl -L https://mirrors.edge.kernel.org/pub/linux/kernel/projects/rt/6.8/patch-6.8.2-rt11.patch.xz -o patch-6.8.2-rt11.patch.xz

$ curl -L https://mirrors.edge.kernel.org/pub/linux/kernel/projects/rt/6.8/older/patch-6.8-rt8.patch.xz -o patch-6.8-rt8.patch.xz

$ cd linux-6.8

```


```shell
$ xzcat ../patch-6.8.2-rt11.patch.xz | patch -p1
1 out of 23 hunks FAILED -- saving rejects to file net/core/dev.c.rej

$ cd ../

$ rm -r linux-6.8
```

```shell
$ xzcat ../patch-6.8-rt8.patch.xz | patch -p1
...
patching file kernel/time/tick-sched.c
patching file kernel/time/timer.c
patching file kernel/trace/trace.c
patching file kernel/trace/trace_output.c
patching file lib/dump_stack.c
patching file localversion-rt
patching file net/core/dev.c
patching file net/core/skbuff.c

```

```shell
$ cp /boot/config-6.8.0-71-generic .config
$ make oldconfig
```

```shell
# choose 5
Preemption Model
  1. No Forced Preemption (Server) (PREEMPT_NONE)
> 2. Voluntary Kernel Preemption (Desktop) (PREEMPT_VOLUNTARY)
  3. Preemptible Kernel (Low-Latency Desktop) (PREEMPT)
  4. Automagic preemption mode with runtime tweaking support (PREEMPT_AUTO) (NEW)
  5. Fully Preemptible Kernel (Real-Time) (PREEMPT_RT) (NEW)
choice[1-5?]:

# hit enter until the end
Undefined behaviour sanity checker (UBSAN) [Y/n/?] y
  Abort on Sanitizer warnings (smaller kernel but less verbose) (UBSAN_TRAP) [N/y/?] n
  Perform array index bounds checking (UBSAN_BOUNDS) [Y/n/?] y
  Perform checking for bit-shift overflows (UBSAN_SHIFT) [Y/n/?] y
  Perform checking for integer divide-by-zero (UBSAN_DIV_ZERO) [N/y/?] n
  Perform checking for non-boolean values used as boolean (UBSAN_BOOL) [Y/n/?] y
  Perform checking for out of bounds enum values (UBSAN_ENUM) [Y/n/?] y
  Perform checking for misaligned pointer usage (UBSAN_ALIGNMENT) [N/y/?] n
  Enable instrumentation for the entire kernel (UBSAN_SANITIZE_ALL) [Y/n/?] (NEW) 
  Module for testing for undefined behavior detection (TEST_UBSAN) [N/m/?] n
#
# configuration written to .config
#
```

```shell
# delete value as below

CONFIG_SYSTEM_TRUSTED_KEYS=""
CONFIG_MODULE_SIG_KEY=""
CONFIG_SYSTEM_REVOCATION_KEYS=""

# comment out

CONFIG_MODULE_SIG_FORCE
CONFIG_DEBUG_INFO_BTF
CONFIG_MODULE_SIG_ALL

```

```shell
$ nproc
4
```

```shell

# $ make -j2 deb-pkg
$ make -j2 bindeb-pkg
```