#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h> 

int init_module(void);
void cleanup_module(void);
static int device_open(struct inode *, struct file *);
static int device_release(struct inode *, struct file *);
static ssize_t device_read(struct file *, char *, size_t, loff_t *);
static ssize_t device_write(struct file *, const char *, size_t, loff_t *);

#define SUCCESS 0
#define DEVICE_NAME "char_dev_driver"
#define BUF_LEN 80


static int dev_major;
static int device_open_counter = 0;
static char msg[BUF_LEN];
static char *msg_buff_ptr;

static struct file_operations fops = {
  .read = device_read,
  .write = device_write,
  .open = device_open,
  .release = device_release
};


int init_module(void)
{
  dev_major = register_chrdev(0, DEVICE_NAME, &fops);

  if (dev_major < 0) {
    printk(KERN_ALERT "Registering char device failed with %d\n", dev_major);
    return dev_major;
  }

  printk(KERN_INFO "I was assigned dev_major number %d. To talk to\n", dev_major);
  printk(KERN_INFO "the driver, create a dev file with\n");
  printk(KERN_INFO "'mknod /dev/%s c %d 0'.\n", DEVICE_NAME, dev_major);
  printk(KERN_INFO "Try various minor numbers. Try to cat and echo to\n");
  printk(KERN_INFO "the device file.\n");
  printk(KERN_INFO "Remove the device file and module when done.\n");

  return SUCCESS;
}


void cleanup_module(void)
{
  unregister_chrdev(dev_major, DEVICE_NAME);
}


static int device_open(struct inode *inode, struct file *filp)
{
  static int counter = 0;

  if (device_open_counter)
    return -EBUSY;

  device_open_counter++;
  sprintf(msg, "I already told you %d times Hello world!\n", counter++);
  msg_buff_ptr = msg;

  try_module_get(THIS_MODULE);

  return SUCCESS;
}


static int device_release(struct inode *inode, struct file *filp)
{
  device_open_counter--;

  module_put(THIS_MODULE);

  return SUCCESS;
}


static ssize_t device_read(struct file *filp, 
                           char *buffer,      
                           size_t length,     
                           loff_t *offset)
{

  int bytes_read = 0;

  if (*msg_buff_ptr == 0)
    return 0;

  while (length && *msg_buff_ptr) {
    put_user(*(msg_buff_ptr++), buffer++);
    length--;
    bytes_read++;
  }

  return bytes_read;
}


static ssize_t device_write(struct file *filp, const char *buf, size_t len, loff_t *off)
{
  printk(KERN_ALERT "Sorry, this operation isn't supported.\n");
  return -EINVAL;
}

// module_init(init_module);
// module_exit(cleanup_module);
MODULE_LICENSE("GPL");