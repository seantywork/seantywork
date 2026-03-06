# struct file_operations

```c
    struct file_operations {
       struct module *owner;
       loff_t (*llseek) (struct file *, loff_t, int);
       ssize_t (*read) (struct file *, char *, size_t, loff_t *);
       ssize_t (*write) (struct file *, const char *, size_t, loff_t *);
       int (*readdir) (struct file *, void *, filldir_t);
       unsigned int (*poll) (struct file *, struct poll_table_struct *);
       int (*ioctl) (struct inode *, struct file *, unsigned int, unsigned long);
       int (*mmap) (struct file *, struct vm_area_struct *);
       int (*open) (struct inode *, struct file *);
       int (*flush) (struct file *);
       int (*release) (struct inode *, struct file *);
       int (*fsync) (struct file *, struct dentry *, int datasync);
       int (*fasync) (int, struct file *, int);
       int (*lock) (struct file *, int, struct file_lock *);
    	 ssize_t (*readv) (struct file *, const struct iovec *, unsigned long,
          loff_t *);
    	 ssize_t (*writev) (struct file *, const struct iovec *, unsigned long,
          loff_t *);
    };

```


# registering file operations

```c
static struct file_operations fops = {
  .llseek = device_llseek,
  .read = device_read,
  .write = device_write,
  .open = device_open,
  .release = device_release
};
```

# design

```shell


+------------------------+
| user       | user      |
| main       | thread    |
|  writes    |  read     |
|  message   |  message  |
+-----|------------^-----+
|     |            |     |
|     V            |     |
| kernel file_operations |                 
|       .llseek          |
|       .read            |
|       .write           |
|       .open            |
|       .release         |
|                        |
+------------------------+


```



# build kernel module and user prog

```shell
$ make
$ cd ./user && make

```

# create character device script
```shell

$ sudo ./dev_create.sh 
dev node created
./user/chr_store
```

```shell
# dmesg -wH
[ +39.686846] chr_store: dev_major number: 239: init

```
# run with message
```shell
$ sudo ./u.out "hello from the other side"
cmd: [w/q] 
main: file opened
thread: failed to open: -1
thread: failed to open: -1

```

```shell
# dmesg -wH
[Nov 6 05:01] file opened: 1
[  +1.000207] not possible to open: already occupied: 1
[  +1.000239] not possible to open: already occupied: 1
[  +1.000297] not possible to open: already occupied: 1
[  +1.000664] not possible to open: already occupied: 1
[  +1.000504] not possible to open: already occupied: 1
[  +1.000295] not possible to open: already occupied: 1

```

# closing without saving

```shell
q
main: quit
thread: closed file
thread: closed file
```

```shell
[  +1.000319] not possible to open: already occupied: 1
[  +0.634617] file closed: 0
[  +0.365655] file opened: 1
[  +0.000102] chr_store: seek: 2
[  +0.000007] chr_store: seek: 0
[  +0.000018] file closed: 0
[  +0.000046] file opened: 1
[  +0.000013] chr_store: seek: 2
[  +0.000004] chr_store: seek: 0
[  +0.000006] file closed: 0

```

# write to the device

```shell

w
target write size: 25
main: file closed
main: file opened
thread: failed to open: 
```

```shell
[  +1.000297] not possible to open: already occupied: 1
[  +0.886453] chr_store: w length: 25
[  +0.000059] file closed: 0
[  +0.000043] file opened: 1
[  +0.113658] not possible to open: already occupied: 1

```

# to see if the other thread can read from device

```shell
q
main: quit
read: 25: hello from the other side
thread: closed file
read: 25: hello from the other side
thread: closed file

```

```shell

[ +12.217694] file opened: 1
[Nov 6 05:04] not possible to open: already occupied: 1
[  +1.000287] not possible to open: already occupied: 1
[  +1.000138] not possible to open: already occupied: 1
[  +0.151953] file closed: 0
[  +0.848280] file opened: 1
[  +0.000044] chr_store: seek: 2
[  +0.000008] chr_store: seek: 0
[  +0.000105] chr_store: r length: 4096
[  +0.000038] file closed: 0
[  +0.000025] file opened: 1
[  +0.000016] chr_store: seek: 2
[  +0.000005] chr_store: seek: 0
[  +0.000006] chr_store: r length: 4096
[  +0.000014] file closed: 0

```

# close file

```shell
$ sudo ./dev_destroy.sh 
dev node destroyed

```
```shell
[ +45.326173] chr_store: dev_major: 239: gone
```