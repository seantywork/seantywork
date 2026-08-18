GCC_FLAGS := -Wall -g

GCC_OBJ_FLAGS := -Wall -c

DEP_PACKAGES := libssl-dev 

DEP_CIVETWEB := git clone https://github.com/civetweb/civetweb.git

DEP_CJSON := git clone https://github.com/DaveGamble/cJSON.git

INCLUDES := -I./server -I./client -I./civetweb/include -I./cJSON

LIBS := -lcivetweb -lpthread -ldl

LINKS := -L./civetweb

SERVER_OBJS := ws_server.o

CLIENT_OBJS := ws_client.o

DEP_OBJS := cJSON.o cJSON_Utils.o

LIB_OBJS := libcivetweb.a

all: 

	@echo "http"


dep-package:

	apt-get update

	apt-get -y install $(DEP_PACKAGES)

dep-source:

	$(DEP_CIVETWEB)

	$(DEP_CJSON)


build: $(SERVER_OBJS) $(CLIENT_OBJS) $(LIB_OBJS) $(DEP_OBJS)

	gcc $(GCC_FLAGS) $(INCLUDES) $(LINKS) -DMG_EXPERIMENTAL_INTERFACES -o server.out server/main.c $(SERVER_OBJS) $(DEP_OBJS) $(LIBS) 

	gcc $(GCC_FLAGS) $(INCLUDES) $(LINKS) -DNO_SSL -DMG_EXPERIMENTAL_INTERFACES -o client.out client/main.c $(CLIENT_OBJS) $(DEP_OBJS) $(LIBS) 


ws_server.o:

	gcc $(GCC_OBJ_FLAGS) $(INCLUDES) -o ws_server.o server/ws_server.c 

ws_client.o:

	gcc $(GCC_OBJ_FLAGS) $(INCLUDES) -o ws_client.o client/ws_client.c 


libcivetweb.a:

	cd civetweb && make clean && make WITH_IPV6=1 WITH_WEBSOCKET=1 COPT='-DMG_EXPERIMENTAL_INTERFACES' lib 

cJSON.o:

	gcc $(GCC_OBJ_FLAGS) $(INCLUDES) -o cJSON.o cJSON/cJSON.c 

cJSON_Utils.o:

	gcc $(GCC_OBJ_FLAGS) $(INCLUDES) -o cJSON_Utils.o cJSON/cJSON_Utils.c 

clean-dep-source:

	rm -r ./vendor/cJSON ./vendor/mongoose

clean:

	rm -r *.o *.out