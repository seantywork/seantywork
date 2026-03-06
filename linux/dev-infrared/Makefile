all: 
	@echo "infrared"

receiver:

	gcc -o irrecv.out ir_recv_main.c  ir_recv.c -lpigpio -lrt -lpthread

transmitter:

	gcc -c -o irsend.o ir_send.c 

	gcc -o irsend.out ir_send_main.c irsend.o -lm -lpigpio -lrt -lpthread 

clean:
	rm -r *.out *.o
