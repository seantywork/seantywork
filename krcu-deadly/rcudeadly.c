#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/spinlock.h>
#include <linux/preempt.h>





static int __init rcu_deadly_init(void){



    return 0;
}

static void __exit rcu_deadly_exit(void){


}

module_init(rcu_deadly_init);
module_exit(rcu_deadly_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("seantywork");