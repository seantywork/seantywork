#include <stdio.h>

#include <pigpio.h>

#include "ir_recv.h"


void callback(uint32_t signal)
{
   printf("signal=%u\n", signal);
}

int main(int argc, char *argv[])
{
   IR_Receiver_t *irrecv;

   if (gpioInitialise() < 0) return 1;

   irrecv = IR_Receiver(4, callback, 5);

   sleep(300);

   IR_Receiver_cancel(irrecv);

   gpioTerminate();
}

