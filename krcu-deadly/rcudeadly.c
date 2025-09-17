#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/spinlock.h>
#include <linux/preempt.h>
#include <linux/kthread.h>
#include <linux/sched/task.h>
#include <linux/delay.h>

#define OP_COUNT 10

static struct task_struct *task_write;
static struct task_struct *task_read;
static int w = 10;
static int r = 11;

static int task_writer(void *arg){

    int v = *(int *)arg;

    for(int i = 0; i < OP_COUNT; i++){
        printk(KERN_INFO "rcudeadly: v: %d: w: %d\n", v, i);
        mdelay(1000);
    }

    return 0;
}

static int task_reader(void *arg){

    int v = *(int *)arg;

    for(int i = 0; i < OP_COUNT; i++){
        printk(KERN_INFO "rcudeadly: v: %d: r: %d\n", v, i);
        mdelay(1000);
    }

    return 0;
}


static int __init rcu_deadly_init(void){

    task_write = kthread_run(task_writer, (void*)&w, "tw/%d", w);
    if(IS_ERR(task_write)){
        printk(KERN_ERR "rcudeadly: failed to create task_write thread\n");
        return -1;
    }
    task_read = kthread_run(task_reader, (void*)&r, "tr/%d", r);
    if(IS_ERR(task_read)){
        printk(KERN_ERR "rcudeadly: failed to create task_read thread\n");
        return -1;
    }
    get_task_struct(task_write);
    get_task_struct(task_read);

    printk(KERN_INFO "rcudeadly: loaded\n");

    return 0;
}

static void __exit rcu_deadly_exit(void){
    kthread_stop(task_write);
    kthread_stop(task_read);

    printk(KERN_INFO "rcudeadly: unloaded\n");

}

module_init(rcu_deadly_init);
module_exit(rcu_deadly_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("seantywork");