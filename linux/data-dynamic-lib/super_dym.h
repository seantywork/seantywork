#ifndef _SUPER_DYM_H_
#define _SUPER_DYM_H_

#define SUPER_DYM_SYM_super_var_init "super_var_init"
#define SUPER_DYM_SYM_super_var_increase "super_var_increase"
#define SUPER_DYM_SYM_super_var_get "super_var_get"
#define SUPER_DYM_SYM_super_var_exit "super_var_exit"
#define SUPER_DYM_SYM_super_var "super_var"

typedef int (*SUPER_DYM_FN_super_var_init)();
typedef void (*SUPER_DYM_FN_super_var_increase)(int by);
typedef int (*SUPER_DYM_FN_super_var_get)();
typedef void (*SUPER_DYM_FN_super_var_exit)();
typedef int SUPER_DYM_VAR_super_var;

extern SUPER_DYM_VAR_super_var super_var;

#endif 