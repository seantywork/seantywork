#include <stdlib.h>

#include <pigpio.h>

#include "ir_recv.h"


struct _IR_Receiver_s
{
   int gpio;
   IR_Receiver_CB_t callback;
   int timeout;
   int in_code;
   uint32_t signal_val;
   int edges;
   int t1;
   int t2;
   int t3;
   int t4;
};



static void _cb(int gpio, int level, uint32_t tick, void *user)
{
   IR_Receiver_t * irrecv;

   irrecv = user;

   if (level != PI_TIMEOUT)
   {
      if (irrecv->in_code == 0)
      {
         irrecv->in_code = 1;

         gpioSetWatchdog(gpio, irrecv->timeout);

         irrecv->signal_val = 0U;

         irrecv->edges = 1;

         irrecv->t1 = 0;
         irrecv->t2 = 0;
         irrecv->t3 = 0;
         irrecv->t4 = tick;
      }
      else
      {
         irrecv->edges++;

         irrecv->t1 = irrecv->t2;
         irrecv->t2 = irrecv->t3;
         irrecv->t3 = irrecv->t4;
         irrecv->t4 = tick;

         if (irrecv->edges > 3)
         {
            irrecv->signal_val = (uint32_t)(irrecv->t4 + irrecv->t3 + irrecv -> t2 + irrecv->t1);

         }
      }
   }
   else
   {
      if (irrecv->in_code)
      {
         irrecv->in_code = 0;

         gpioSetWatchdog(gpio, 0);

         if (irrecv->edges > 12) /* Anything less is probably noise. */
         {
            (irrecv->callback)(irrecv->signal_val);
         }
      }
   }
}

IR_Receiver_t *IR_Receiver(int gpio, IR_Receiver_CB_t callback, int timeout)
{
   IR_Receiver_t *irrecv;

   irrecv = malloc(sizeof(IR_Receiver_t));

   irrecv->gpio     = gpio;
   irrecv->callback = callback;
   irrecv->timeout  = 5;

   irrecv->in_code = 0;

   gpioSetMode(gpio, PI_INPUT);
   gpioSetAlertFuncEx(gpio, _cb, irrecv);

   return irrecv;
}

void IR_Receiver_cancel(IR_Receiver_t *irrecv)
{
   if (irrecv)
   {
      gpioSetAlertFunc(irrecv->gpio, 0);

      free(irrecv);

      irrecv = NULL;
   }
}

