

# find out context 

```c
static void show_proc_context(char* buf){
    unsigned int uid;
    if(likely(in_task())){
        uid = from_kuid(&init_user_ns, current_uid());
        snprintf(buf, KPROC_BUFF_LEN, "kproc: ctx: process: uid: %u: pid: %d", uid, task_pid_nr(current));
    } else {
        snprintf(buf, KPROC_BUFF_LEN, "kproc: ctx: interrupt");
    }
}

```

# kernel syscall handling

```c
static ssize_t device_read(struct file *filp, char *buffer, size_t len, loff_t *offset){
    char tmp_msg_buffer[KPROC_BUFF_LEN] = {0};
    show_proc_context(tmp_msg_buffer);
    ssize_t n = copy_to_user(buffer, tmp_msg_buffer, KPROC_BUFF_LEN);
    (*offset) += KPROC_BUFF_LEN;
    return KPROC_BUFF_LEN - n;
}

```

# kernel interrupt handling

```c

#define IRQ_1 1
#define IRQ_1_DEV "keyboard"
#define IRQ_1_ID "0001"

// ...

char tmp_msg_buffer[KPROC_BUFF_LEN] = {0};

static irq_handler_t irq_1_handler(unsigned int irq, void* dev_id, struct pt_regs *regs){
    show_proc_context(tmp_msg_buffer);
    printk("kproc: isr: %s\n", tmp_msg_buffer);
    memset(tmp_msg_buffer, 0, KPROC_BUFF_LEN);
    return (irq_handler_t)IRQ_HANDLED;
}
```

# insmod kproc.ko
```shell
[Nov21 03:22] kproc: hello
```

# ./user/user.out

```shell
devices:
Character devices:
  1 mem
  4 /dev/vc/0
  4 tty
  4 ttyS
  5 /dev/tty
  5 /dev/console
  5 /dev/ptmx
  5 ttyprintk
  7 vcs
 10 misc
 ...

```

```shell
239 kproc_f
target major: 239
main: kproc: ctx: process: uid: 0: pid: 109635
thread: kproc: ctx: process: uid: 0: pid: 109636
main: kproc: ctx: process: uid: 0: pid: 109635
thread: kproc: ctx: process: uid: 0: pid: 109636
main: kproc: ctx: process: uid: 0: pid: 109635
thread: kproc: ctx: process: uid: 0: pid: 109636
main: kproc: ctx: process: uid: 0: pid: 109635
thread: kproc: ctx: process: uid: 0: pid: 109636
main: kproc: ctx: process: uid: 0: pid: 109635
thread: kproc: ctx: process: uid: 0: pid: 109636
main: kproc: ctx: process: uid: 0: pid: 109635
thread: kproc: ctx: process: uid: 0: pid: 109636
^CSIG: 2
```

```shell
[Nov21 03:23] file opened: 1
[  +5.292114] file closed: 0
```

# interrupt on another terminal

```shell
[Nov21 03:25] kproc: isr: kproc: ctx: interrupt
[  +0.000136] kproc: isr: kproc: ctx: interrupt
[  +0.184034] kproc: isr: kproc: ctx: interrupt
[  +0.000194] kproc: isr: kproc: ctx: interrupt
[  +1.263342] kproc: isr: kproc: ctx: interrupt
[  +0.000102] kproc: isr: kproc: ctx: interrupt
[  +0.143710] kproc: isr: kproc: ctx: interrupt
[  +0.000103] kproc: isr: kproc: ctx: interrupt
[  +9.776542] kproc: isr: kproc: ctx: interrupt
[  +0.151752] kproc: isr: kproc: ctx: interrupt
[  +0.151249] kproc: isr: kproc: ctx: interrupt

```

# rmmod 

```shell
[ +30.320705] kproc: bye
```