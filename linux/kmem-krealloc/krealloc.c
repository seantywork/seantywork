
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>

#define OURMODNAME   "slab1_krealloc"

MODULE_AUTHOR("seantywork");
MODULE_LICENSE("Dual MIT/GPL");
MODULE_VERSION("0.1");

static char *gkptr;

static int __init slab1_init(void)
{
	gkptr = kmalloc(1024, GFP_KERNEL);
	if (!gkptr) {
		goto out_fail1;
	}
	pr_info("%s: context struct realloc'ed (actual KVA ret = %px)\n",
		OURMODNAME, gkptr);
	print_hex_dump_bytes("ptr: ", DUMP_PREFIX_OFFSET, gkptr, 32);

	gkptr = krealloc(gkptr, 2048, GFP_KERNEL);
	if (!gkptr){
		goto out_fail2;
    }
	pr_info("%s: context struct realloc'ed (actual KVA ret = %px)\n",
		OURMODNAME, gkptr);
	print_hex_dump_bytes("ptr: ", DUMP_PREFIX_OFFSET, gkptr, 32);
	return 0;		/* success */

 out_fail2:
	kfree(gkptr);
 out_fail1:
	return -ENOMEM;
}

static void __exit slab1_exit(void)
{
	kfree(gkptr);
	pr_info("%s: freed slab memory, removed\n", OURMODNAME);
}

module_init(slab1_init);
module_exit(slab1_exit);