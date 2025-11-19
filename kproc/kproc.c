#include <linux/init.h> 
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h> 
#include <linux/errno.h>  
#include <linux/sched.h>
#include <linux/sched/signal.h>

#include <linux/fs.h>
#include <linux/uaccess.h> 

#include <linux/delay.h>
#include <linux/workqueue.h>

#include "kproc.h"

#define DEVICE_NAME "kproc_f"

static struct work_struct job;

static int dev_major;
static int device_open_counter = 0;
static int work_done = 0;

static void show_proc_context(char* buf){
    unsigned int uid;
    if(likely(in_task())){
        uid = from_kuid(&init_user_ns, current_uid());
        snprintf(buf, KPROC_BUFF_LEN, "kproc: ctx: process: uid: %u: pid: %d\n", uid, task_pid_nr(current));
    } else {
        snprintf(buf, KPROC_BUFF_LEN, "kproc: ctx: interrupt\n");
    }
}


static int device_open(struct inode *inode, struct file *filp){
  if (device_open_counter){
    printk(KERN_INFO "not possible to open: already occupied: %d\n", device_open_counter);
    return -EBUSY;
  }
  device_open_counter++;
  printk(KERN_INFO "file opened: %d\n", device_open_counter);
  try_module_get(THIS_MODULE);
  return 0;
}


static int device_release(struct inode *inode, struct file *filp){
  device_open_counter--;
  printk(KERN_INFO "file closed: %d\n", device_open_counter);
  module_put(THIS_MODULE);
  return 0;
}
static ssize_t device_read(struct file *filp, char *buffer, size_t len, loff_t *offset){
    char tmp_msg_buffer[KPROC_BUFF_LEN] = {0};
    show_proc_context(tmp_msg_buffer);
    ssize_t n = copy_to_user(buffer, tmp_msg_buffer, len);
    (*offset) += len;
    return KPROC_BUFF_LEN - n;
}

static ssize_t device_write(struct file *filp, const char *buf, size_t len, loff_t *offset){
    printk(KERN_ALERT "kproc: write not allowed\n");
    return -EINVAL;
}

static void job_handler(struct work_struct* work){
    printk("kproc: job scheduled\n");
    char tmp_msg_buffer[KPROC_BUFF_LEN] = {0};
    while(!work_done){
        show_proc_context(tmp_msg_buffer);
        printk("kproc: job: %s\n", tmp_msg_buffer);
        memset(tmp_msg_buffer, 0, KPROC_BUFF_LEN);
        msleep(3000);
    }
    printk("kproc: job done\n");
}

static struct file_operations fops = {
  .read = device_read,
  .write = device_write,
  .open = device_open,
  .release = device_release
};

static int __init kproc_init(void){
    dev_major = register_chrdev(0, DEVICE_NAME, &fops);
    if (dev_major < 0) {
        printk(KERN_ALERT "registering char device failed with %d\n", dev_major);
        return dev_major;
    }
    INIT_WORK(&job, job_handler);
    schedule_work(&job);
    printk("kproc: hello\n");
    return 0;
}

static void __exit kproc_exit(void){
    work_done = 1;
    printk("kproc: exit: waiting 5 seconds\n");
    msleep(5000);
    unregister_chrdev(dev_major, DEVICE_NAME);
    printk("kproc: bye\n");
}

module_init(kproc_init);
module_exit(kproc_exit);

MODULE_LICENSE("GPL");