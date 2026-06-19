#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/percpu.h>
#include <linux/percpu-defs.h>

typedef struct mypercpu_data {
    int data;
} mypercpu_data;


DEFINE_PER_CPU(mypercpu_data, pd);

static mypercpu_data* pdptr = NULL;

static int __init percpu_init(void) {
    int data = 0;
    printk(KERN_INFO "per cpu init\n");
    // never sleep between the two
    get_cpu_var(pd).data = 1;
    put_cpu_ptr(pd);
    data = get_cpu_var(pd).data;
    put_cpu_ptr(pd);
    printk(KERN_INFO "cpu var: %d\n", data);
    pdptr = (mypercpu_data __percpu*)alloc_percpu_gfp(mypercpu_data, GFP_KERNEL);
    get_cpu_ptr(pdptr)->data = 2;
    put_cpu_ptr(pdptr);
    data = get_cpu_ptr(pdptr)->data;
    put_cpu_ptr(pdptr);
    printk(KERN_INFO "cpu ptr: %d\n", data);
	return 0;
}

static void __exit percpu_exit(void) {
    mypercpu_data* _pdptr = get_cpu_ptr(pdptr);
    if(_pdptr != NULL){
        put_cpu_ptr(pdptr);
        free_percpu(pdptr);
    }
    printk(KERN_INFO "per pcu exit\n");

}

module_init(percpu_init);
module_exit(percpu_exit);

MODULE_LICENSE("GPL");