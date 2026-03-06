

FLAGS := -Wall -g

INCLUDES := -Imsquic/src/inc -Imsquic/build/_deps/opensslquic-build/quictls/include -I.

LINKS := -Lmsquic/build/obj/Release -Lmsquic/build/bin/Release -Wl,-rpath=msquic/build/bin/Release
LINKS += -Lmsquic/build/_deps/opensslquic-build/quictls/lib -Lmsquic/build/_deps/opensslquic-build/submodules/quictls

LIBS :=  -lcore -lmsquic -lmsquic_platform -lssl -lcrypto

all:


	gcc $(FLAGS) $(INCLUDES) $(LINKS) -o client.out client/client.c $(LIBS)

	gcc $(FLAGS) $(INCLUDES) $(LINKS) -o server.out server/server.c $(LIBS)

clean:

	rm -rf *.o *.out