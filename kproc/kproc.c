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

#include <linux/interrupt.h>


#include "kproc.h"

#define IRQ_1 1
#define IRQ_1_DEV "irq_1_dev"
#define IRQ_1_ID "0001"

static int dev_major;
static int device_open_counter = 0;

static void show_proc_context(char* buf){
    unsigned int uid;
    if(likely(in_task())){
        uid = from_kuid(&init_user_ns, current_uid());
        snprintf(buf, KPROC_BUFF_LEN, "kproc: ctx: process: uid: %u: pid: %d", uid, task_pid_nr(current));
    } else {
        snprintf(buf, KPROC_BUFF_LEN, "kproc: ctx: interrupt");
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
    ssize_t n = copy_to_user(buffer, tmp_msg_buffer, KPROC_BUFF_LEN);
    (*offset) += KPROC_BUFF_LEN;
    return KPROC_BUFF_LEN - n;
}

static ssize_t device_write(struct file *filp, const char *buf, size_t len, loff_t *offset){
    printk(KERN_ALERT "kproc: write not allowed\n");
    return -EINVAL;
}


char tmp_msg_buffer[KPROC_BUFF_LEN] = {0};

static irq_handler_t irq_1_handler(unsigned int irq, void* dev_id, struct pt_regs *regs){
    show_proc_context(tmp_msg_buffer);
    printk("kproc: isr: %s\n", tmp_msg_buffer);
    memset(tmp_msg_buffer, 0, KPROC_BUFF_LEN);
    return (irq_handler_t)IRQ_HANDLED;
}


static struct file_operations fops = {
  .read = device_read,
  .write = device_write,
  .open = device_open,
  .release = device_release
};

static int __init kproc_init(void){
    if (request_irq(IRQ_1, (irq_handler_t)irq_1_handler, IRQF_SHARED, IRQ_1_DEV, IRQ_1_ID) != 0){
        printk("can't request interrupt number %d\n", IRQ_1);
    }
    dev_major = register_chrdev(0, DEVICE_NAME, &fops);
    if (dev_major < 0) {
        free_irq(IRQ_1, IRQ_1_ID);
        printk(KERN_ALERT "registering char device failed with %d\n", dev_major);
        return dev_major;
    }
    printk("kproc: hello\n");
    return 0;
}

static void __exit kproc_exit(void){
    free_irq(IRQ_1, IRQ_1_ID);
    unregister_chrdev(dev_major, DEVICE_NAME);
    printk("kproc: bye\n");
}

module_init(kproc_init);
module_exit(kproc_exit);

MODULE_LICENSE("GPL");