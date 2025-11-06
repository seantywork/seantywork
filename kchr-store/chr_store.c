#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h> 
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/string.h>

#define SUCCESS 0
#define DEVICE_NAME "chr_store"
#define MAX_LEN 256
#define BLK_LEN 4096

static int dev_major;
static int device_open_counter = 0;
static int blk_count = 0;
static __u8* msg = NULL;

static int device_open(struct inode *inode, struct file *filp){
  if (device_open_counter){
    printk(KERN_INFO "not possible to open: already occupied: %d\n", device_open_counter);
    return -EBUSY;
  }
  device_open_counter++;
  printk(KERN_INFO "file opened: %d\n", device_open_counter);
  try_module_get(THIS_MODULE);
  return SUCCESS;
}


static int device_release(struct inode *inode, struct file *filp){
  device_open_counter--;
  printk(KERN_INFO "file closed: %d\n", device_open_counter);
  module_put(THIS_MODULE);
  return SUCCESS;
}


static ssize_t device_read(struct file *filp, char *buffer, size_t len, loff_t *offset){
  int _blk_count = 0;
  ssize_t n = 0;
  printk(KERN_INFO "chr_store: r length: %lu\n", len);
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
  printk(KERN_INFO "chr_store: w length: %lu\n", len);
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

static loff_t device_llseek(struct file* filp, loff_t offset, int whence){

  loff_t retval = 0;
  printk(KERN_INFO "chr_store: seek: %d\n", whence);
  if(blk_count == 0){
    return 0;
  }
  switch(whence){
    case SEEK_END:
      retval = strlen(msg);      
      break;
    case SEEK_SET:
      retval = 0;
      break;
    default:
      retval = 0;
      break;
  }
  return retval;
}




static struct file_operations fops = {
  .llseek = device_llseek,
  .read = device_read,
  .write = device_write,
  .open = device_open,
  .release = device_release
};


static int __init init_chr_store(void){
  dev_major = register_chrdev(0, DEVICE_NAME, &fops);
  if (dev_major < 0) {
    printk(KERN_ALERT "registering char device failed with %d\n", dev_major);
    return dev_major;
  }
  printk(KERN_INFO "chr_store: dev_major number: %d: init\n", dev_major);
  return SUCCESS;
}


static void __exit exit_chr_store(void){
  unregister_chrdev(dev_major, DEVICE_NAME);
  if(msg != NULL){
    kfree(msg);
  }
  printk(KERN_INFO "chr_store: dev_major: %d: gone\n", dev_major);
}

module_init(init_chr_store);
module_exit(exit_chr_store);
MODULE_LICENSE("GPL");