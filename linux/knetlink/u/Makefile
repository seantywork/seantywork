ALL :=  prod prod_2part

###
# Update as required
# Simply replace the variable ${FNAME_C} below (currently set to 'killer'),
# with your program name!
# Of course, if you have >1 C program to build, you must add it manually.
# Also, it's recommended to keep one Makefile per program in separate directories.
###
FNAME_C = uapp
ALL_NM :=  ${FNAME_C} ${FNAME_C}_dbg ${FNAME_C}_dbg_asan ${FNAME_C}_dbg_ub ${FNAME_C}_gcov

CC=${CROSS_COMPILE}gcc
CL=${CROSS_COMPILE}clang
STRIP=${CROSS_COMPILE}strip

PROD_OPTLEVEL=-O2
  # or -O3 or -Os
CFLAGS=-Wall -UDEBUG ${PROD_OPTLEVEL}
# Dynamic analysis includes the compiler itself!
# Especially the powerful Address Sanitizer (ASAN) toolset
CFLAGS_DBG=-g -ggdb -gdwarf-4 -O0 -Wall -Wextra -DDEBUG
CFLAGS_DBG_ASAN=${CFLAGS_DBG} -fsanitize=address
CFLAGS_DBG_UB=${CFLAGS_DBG} -fsanitize=undefined
#CFLAGS_DBG_MSAN=${CFLAGS_DBG} -fsanitize=memory

CFLAGS_GCOV=${CFLAGS_DBG} -fprofile-arcs -ftest-coverage

# Required vars
all: ${ALL}
SRC_FILES := *.[ch]
# INDENT := indent
# FLAWFINDER := flawfinder
# CPPCHECK := cppcheck
# VALGRIND := valgrind
# update as required
PKG_NAME := ${FNAME_C}
KDIR ?= /lib/modules/$(shell uname -r)/build
CHECKPATCH := ${KDIR}/scripts/checkpatch.pl
CLANG_CHECK := clang-check

# Targets and their rules
# Three types:
# 1. prod: 'regular' production target: -O2, no debug symbolic info, stripped
# 2. prod_2part: a '2-part' production target: -O2, no debug symbolic info, strip-debug;
#     excellent for production as it gives ability to debug as and when required!
#     (internally invokes the 'debug' target as it requires the debug binary as well
# 3. debug target(s): -O0, debug symbolic info (-g -ggdb), not stripped
prod: ${FNAME_C}.c
	@echo
	@echo "--- building 'production'-ready target (-O2, no debug, stripped) ---"
	@echo
	${CC} ${CFLAGS} ${FNAME_C}.c -o ${FNAME_C}
	${STRIP} --strip-all ./${FNAME_C}

# The '2-part executable' solution : use strip and objcopy to generate a
# binary executable that has the ability to retrieve debug symbolic information
# from the 'debug' binary!
prod_2part: ${FNAME_C}.c
	@echo
	@echo "--- building 'production'-ready 2-part target (-O2, no debug, strip-debug) ---"
	@echo
# We require the 'debug' build for the 2part, so do that first
	make debug
	${CC} ${CFLAGS} ${FNAME_C}.c -o ${FNAME_C}
	${STRIP} --strip-debug ./${FNAME_C}
	objcopy --add-gnu-debuglink=./${FNAME_C}_dbg ./${FNAME_C}

debug: ${FNAME_C}.c
	@echo
	@echo "--- building 'debug'-ready targets (with debug symbolic info, not stripped) ---"
	@echo
	${CC} ${CFLAGS_DBG} ${FNAME_C}.c -o ${FNAME_C}_dbg
#-- Sanitizers (use clang or gcc)
	${CC} ${CFLAGS_DBG_ASAN} ${FNAME_C}.c -o ${FNAME_C}_dbg_asan
	${CC} ${CFLAGS_DBG_UB} ${FNAME_C}.c -o ${FNAME_C}_dbg_ub
#	${CC} ${CFLAGS_DBG_MSAN} ${FNAME_C}.c -o ${FNAME_C}_dbg_msan

clean:
	@echo
	@echo "--- cleaning ---"
	@echo
	rm -vf ${ALL_NM} core* vgcore* *.o *~ *.c.gcov *.gcda *.gcno *.c.ast