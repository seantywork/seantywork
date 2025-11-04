#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h> 
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/string.h>

#define SUCCESS 0
#define DEVICE_NAME "mem_storage"
#define MAX_LEN 256
#define BLK_LEN 4096

static int dev_major;
static int device_open_counter = 0;
static int blk_count = 0;
static __u8* msg = NULL;

static int device_open(struct inode *inode, struct file *filp){
  if (device_open_counter){
    return -EBUSY;
  }
  device_open_counter++;
  try_module_get(THIS_MODULE);
  return SUCCESS;
}


static int device_release(struct inode *inode, struct file *filp){
  device_open_counter--;
  module_put(THIS_MODULE);
  return SUCCESS;
}


static ssize_t device_read(struct file *filp, char *buffer, size_t len, loff_t *offset){
  int _blk_count = 0;
  ssize_t n = 0;
  printk(KERN_INFO "mst: r length: %lu\n", len);
  if (blk_count == 0){
    return 0;
  }
  _blk_count = len / BLK_LEN;
  if(len % BLK_LEN != 0){
    _blk_count += 1;
  }
  if(_blk_count > MAX_LEN){
    printk(KERN_ERR "requested data out of range\n");
    return -EINVAL;
  }
  n = copy_to_user(buffer, msg, len);
  (*offset) += len;
  return len - n;
}


static ssize_t device_write(struct file *filp, const char *buf, size_t len, loff_t *offset){

  int _blk_count = 0;
  ssize_t n = 0;
  printk(KERN_INFO "mst: w length: %lu\n", len);
  _blk_count = len / BLK_LEN;
  if(len % BLK_LEN != 0){
    _blk_count += 1;
  }
  if(_blk_count > MAX_LEN){
    printk(KERN_ERR "invalid total length\n");
    return -EINVAL;
  }
  if(_blk_count == 0){
    if(msg != NULL){
      blk_count = 0;
      kfree(msg);
    }
    return 0;
  }
  if(msg == NULL){
    msg = kzalloc(_blk_count * BLK_LEN,GFP_KERNEL);
    if(msg == NULL){
      printk(KERN_ERR "failed to add new data\n");
      return -ENOMEM;
    }
    n = copy_from_user(msg, buf, len);
  } else {
    memset(msg, blk_count * BLK_LEN, 0);
    if(blk_count != _blk_count){
      msg = krealloc(msg, _blk_count * BLK_LEN, GFP_KERNEL);
    } 
    n = copy_from_user(msg, buf, len);
  }
  (*offset) += len;
  blk_count = _blk_count;
  return len - n;
}


static struct file_operations fops = {
  .read = device_read,
  .write = device_write,
  .open = device_open,
  .release = device_release
};


static int __init init_mem_storage(void){
  dev_major = register_chrdev(0, DEVICE_NAME, &fops);
  if (dev_major < 0) {
    printk(KERN_ALERT "registering char device failed with %d\n", dev_major);
    return dev_major;
  }
  printk(KERN_INFO "dev_major number: %d\n", dev_major);
  return SUCCESS;
}


static void __exit exit_mem_storage(void){
  unregister_chrdev(dev_major, DEVICE_NAME);
  if(msg != NULL){
    kfree(msg);
  }
  printk(KERN_INFO "dev_major: %d: gone\n", dev_major);
}

module_init(init_mem_storage);
module_exit(exit_mem_storage);
MODULE_LICENSE("GPL");