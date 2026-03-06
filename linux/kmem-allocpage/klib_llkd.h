
#ifndef __KLIB_LKP_H__
#define __KLIB_LKP_H__

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <asm/io.h>		/* virt_to_phys(), phys_to_virt(), ... */

void llkd_minsysinfo(void);
u64 powerof(int base, int exponent);
void show_phy_pages(const void *kaddr, size_t len, bool contiguity_check);
void show_sizeof(void);

#endif