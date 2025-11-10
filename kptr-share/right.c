#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/mutex.h>

typedef struct left_messsage_shared {
    char* message;
    struct mutex lock;  
} left_messsage_shared;

extern left_messsage_shared** get_left_message_address(void);

static int __init right_init(void){
    printk("RIGHT: init\n");
    left_messsage_shared** lms = get_left_message_address();
    printk("(RIGHT)LEFT ADDR: %px\n", (void*)lms);
    mutex_lock(&(*lms)->lock);
    printk("(RIGHT)LEFT MESSAGE: %s\n",(*lms)->message);
    strcpy((*lms)->message, "new message from right");
    printk("RIGHT: wrote new message\n");
    mutex_unlock(&(*lms)->lock);
    return 0;
}

static void __exit right_exit(void){
    printk("exit: right done\n");
}

module_init(right_init);
module_exit(right_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("seantywork");