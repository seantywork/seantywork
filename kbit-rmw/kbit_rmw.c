#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/bitops.h>
#include <linux/atomic.h>


static unsigned long mem;
static int MSB = BITS_PER_BYTE - 1;
#define SHOW_MEM(msg) do { \
    pr_info("%27s: mem : %3ld = 0x%02lx\n", msg, mem, mem); \
} while (0)

static int __init bitrmw_init(void) {
    int ret = -1;
    SHOW_MEM("start");
    set_bit(MSB, &mem);
    SHOW_MEM("done set bit");
    clear_bit(MSB, &mem);
    SHOW_MEM("done clear bit");
    change_bit(MSB, &mem);
    SHOW_MEM("done change bit");
    ret = test_and_set_bit(0, &mem);
    SHOW_MEM("done test set bit at 0");
    pr_info("ret: %d\n", ret);
    ret = test_and_clear_bit(0, &mem);
    SHOW_MEM("done test clear bit at 0");
    pr_info("ret: %d\n", ret);
    ret = test_and_change_bit(1, &mem);
    SHOW_MEM("done test change bit at 1");
    pr_info("ret: %d\n", ret);
    return 0;
}

static void __exit bitrmw_exit(void) {

}

module_init(bitrmw_init);
module_exit(bitrmw_exit);

MODULE_LICENSE("GPL");




