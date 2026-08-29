INFO := "dev, release"

CC := gcc


ifeq ($(CC), gcc)

	ifeq ($(ANA),y)

		FLAG := -fanalyzer -Wall -Wextra

	else 
		FLAG := -Wall -Wextra
	endif

endif


ifeq ($(CC), gcc)
	LINT := cppcheck --enable=all
else 
	LINT := clang-tidy -checks="*"
endif

CC_DEV_FLAGS := -Wall -g 

CC_REL_FLAGS := -Wall

CC_OBJ_FLAGS := $(FLAG) -c -g

CC_DEP_OBJ_FLAGS := -c -g


DEP_PACKAGES := libssl-dev


INCLUDES := -I./include 

LIBS := -lpthread -lssl -lcrypto 


OBJS := ctl.o
OBJS += utils.o
OBJS += sock.o

CLI_OBJS := cli.o
CLI_OBJS += utils.o


LINT_LIST := lint_ctl
LINT_LIST := lint_utils
LINT_LIST := lint_sock 
LINT_LIST := lint_cli


all: 

	@echo $(INFO)


deps:

	apt-get update

	apt-get -y install $(DEP_PACKAGES)


dev: $(OBJS) $(CLI_OBJS) $(DEP_OBJS)

	$(CC) $(CC_DEV_FLAGS) $(INCLUDES) -o engine.out cmd/engine/main.c $(OBJS) $(DEP_OBJS) $(LIBS) 

	$(CC) $(CC_DEV_FLAGS) $(INCLUDES) -o cli.out cmd/cli/main.c $(CLI_OBJS) $(LIBS) 



release: $(OBJS) $(DEP_OBJS)

	$(CC) $(CC_REL_FLAGS) $(INCLUDES) -o engine.out cmd/engine/main.c $(OBJS) $(DEP_OBJS) $(LIBS) 

	$(CC) $(CC_REL_FLAGS) $(INCLUDES) -o cli.out cmd/cli/main.c $(CLI_OBJS) $(LIBS) 


lint: $(LINT_LIST) 

ctl.o:

	$(CC) $(CC_OBJ_FLAGS) $(INCLUDES) -o ctl.o src/ctl.c 


utils.o:

	$(CC) $(CC_OBJ_FLAGS) $(INCLUDES) -o utils.o src/utils.c 

sock.o:

	$(CC) $(CC_OBJ_FLAGS) $(INCLUDES) -o sock.o src/sock/sock.c 


cli.o:

	$(CC) $(CC_OBJ_FLAGS) $(INCLUDES) -o cli.o src/cli/cli.c 



lint_ctl:

ifeq ($(CC),gcc)
	$(LINT) $(INCLUDES) src/ctl.c 
else 
	$(LINT) src/ctl.c  -- $(INCLUDES)
endif


lint_utils:
ifeq ($(CC),gcc)
	$(LINT) $(INCLUDES) src/utils.c 
else 
	$(LINT) src/utils.c  -- $(INCLUDES)
endif

lint_sock:
ifeq ($(CC),gcc)
	$(LINT) $(INCLUDES) src/sock/sock.c 
else 
	$(LINT) src/sock/sock.c  -- $(INCLUDES)
endif


lint_cli:
ifeq ($(CC),gcc)
	$(LINT) $(INCLUDES) src/cli/cli.c 
else 
	$(LINT) src/cli/cli.c  -- $(INCLUDES)
endif


clean:

	rm -rf *.o *.out *.txt

