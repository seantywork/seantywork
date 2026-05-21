#ifndef _SUPER_DYM_H_
#define _SUPER_DYM_H_

#define SUPER_DYM_SYM_super_var_increase "super_var_increase"
#define SUPER_DYM_SYM_super_var_get "super_var_get"

typedef void (*SUPER_DYM_FN_super_var_increase)(int by);
typedef int (*SUPER_DYM_FN_super_var_get)();

#endif 