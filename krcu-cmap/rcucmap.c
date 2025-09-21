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

struct node {
    int key;
    int value;
	struct list_head _node;
	struct rcu_head _rcu;
};

struct cc_buck {
    struct list_head nodes;
    spinlock_t lock;
};

struct cc_map {
    struct cc_buck* buckets;
    int count;
};

static struct cc_map* cmap;
static struct task_struct *task_write;
static struct task_struct *task_read;
static int w = 10;
static int r = 11;


static int _hashfunc(__u32 key, __u32 bcount){
    __u32 hash = ((key >> 16) ^ key) * 0x45d9f3bu;
    hash = ((hash >> 16) ^ hash) * 0x45d9f3bu;
    hash = (hash >> 16) ^ hash;
    return hash % bcount;
}

static struct cc_map* make_ccmap(int bcount){

    struct cc_map* cmap = (struct cc_map*)kzalloc(sizeof(struct cc_map), GFP_KERNEL);
    cmap->count = bcount;
    cmap->buckets = (struct cc_buck*)kzalloc(sizeof(struct cc_buck) * cmap->count, GFP_KERNEL);
    for(int i = 0; i < cmap->count; i++){
        spin_lock_init(&cmap->buckets[i].lock);
        INIT_LIST_HEAD(&cmap->buckets[i].nodes);
    }
    return cmap;    
}

static void _ccmap_cb(struct rcu_head* _rcu){
    struct node* n = container_of(_rcu, struct node, _rcu);
    kfree(n);
}

static int update_ccmap(struct cc_map* cmap, int key, int value){
    int result = -1;
    struct node* n = NULL;
    struct node* old_n = NULL;
    struct node* new_n = NULL;
    __u32 idx = _hashfunc((__u32)key, (__u32)cmap->count);
    rcu_read_lock();
    spin_lock(&cmap->buckets[idx].lock);
    list_for_each_entry(n, &cmap->buckets[idx].nodes, _node){
        if(n->key != key){
            continue;
        }
        old_n = n;
        break;
    }
    new_n = kzalloc(sizeof(struct node), GFP_ATOMIC);
    if(new_n == NULL){
        goto done;
    }
    if(old_n == NULL){
        new_n->key = key;
        new_n->value = value;
        list_add_rcu(&new_n->_node, &cmap->buckets[idx].nodes);
    } else {
        memcpy(new_n, old_n, sizeof(struct node));
        new_n->value = value;
        list_replace_rcu(&old_n->_node, &new_n->_node);
    }
    result = (int)idx;

done:
    spin_unlock(&cmap->buckets[idx].lock);
    rcu_read_unlock();
//    synchronize_rcu();
//    if(old_n != NULL && new_n != NULL){
//        kfree(old_n);
//    }
    if(old_n != NULL && new_n != NULL){
        call_rcu(&old_n->_rcu, _ccmap_cb);
    }
    return result;
}


static int remove_ccmap(struct cc_map* cmap, int key){
    int result = -1;
    struct node* n = NULL;
    struct node* found_n = NULL;
    __u32 idx = _hashfunc((__u32)key, (__u32)cmap->count);
    rcu_read_lock();
    spin_lock(&cmap->buckets[idx].lock);
    list_for_each_entry(n, &cmap->buckets[idx].nodes, _node){
        if(n->key != key){
            continue;
        }
        found_n = n;
        break;
    }
    if(found_n == NULL){
        goto done;
    }
    list_del_rcu(&found_n->_node);
    result = (int)idx;
done:
    spin_unlock(&cmap->buckets[idx].lock);
    rcu_read_unlock();
    if(found_n != NULL){
        call_rcu(&found_n->_rcu, _ccmap_cb);
    }
    return result;
}

static void delete_ccmap(struct cc_map* cmap){
    if(cmap == NULL){
        return;
    }
    struct node* n = NULL;
    struct node* tmp_n = NULL;
    for(int i = 0; i < cmap->count; i++){
        spin_lock(&cmap->buckets[i].lock);
        list_for_each_entry_safe(n, tmp_n, &cmap->buckets[i].nodes, _node){
            list_del(&n->_node);
            kfree(n);
        }
        spin_unlock(&cmap->buckets[i].lock);
        kfree(&cmap->buckets[i]);
    }
    kfree(cmap);

}

static int task_writer(void *arg){

    int v = *(int *)arg;

    for(int i = 0; i < OP_COUNT; i++){
        printk(KERN_INFO "rcucmap: v: %d: w: %d\n", v, i);
        mdelay(1000);
    }

    return 0;
}

static int task_reader(void *arg){

    int v = *(int *)arg;

    for(int i = 0; i < OP_COUNT; i++){
        printk(KERN_INFO "rcucmap: v: %d: r: %d\n", v, i);
        mdelay(1000);
    }

    return 0;
}


static int __init rcu_cmap_init(void){


    /*
    task_write = kthread_run(task_writer, (void*)&w, "tw/%d", w);
    if(IS_ERR(task_write)){
        printk(KERN_ERR "rcucmap: failed to create task_write thread\n");
        return -1;
    }
    task_read = kthread_run(task_reader, (void*)&r, "tr/%d", r);
    if(IS_ERR(task_read)){
        printk(KERN_ERR "rcucmap: failed to create task_read thread\n");
        return -1;
    }
    get_task_struct(task_write);
    get_task_struct(task_read);
    */

    printk(KERN_INFO "rcucmap: init\n");
    cmap = make_ccmap(OP_COUNT);
    printk(KERN_INFO "rcucmap: updating cmap\n");
    for(int i = 0 ; i < OP_COUNT; i++){
        int idx = update_ccmap(cmap, i, i);
        printk(KERN_INFO "update cmap: %d\n", idx);
    }
    printk(KERN_INFO "rcucmap: removing from cmap\n");
    for(int i = 0 ; i < OP_COUNT; i++){
        int idx = remove_ccmap(cmap, i);
        printk(KERN_INFO "remove cmap: %d\n", idx);
    }
    printk(KERN_INFO "rcucmap: done\n");

    return 0;
}

static void __exit rcu_cmap_exit(void){
    /*
    kthread_stop(task_write);
    kthread_stop(task_read);
    */

    printk(KERN_INFO "rcucmap: deleting cmap\n");
    delete_ccmap(cmap);
    printk(KERN_INFO "rcucmap: exit\n");

}

module_init(rcu_cmap_init);
module_exit(rcu_cmap_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("seantywork");