#ifndef IR_RECEIVER_H
#define IR_RECEIVER_H

#include <stdint.h>

typedef void (*IR_Receiver_CB_t)(uint32_t);

struct _IR_Receiver_s;

typedef struct _IR_Receiver_s IR_Receiver_t;

IR_Receiver_t * IR_Receiver(int gpio, IR_Receiver_CB_t callback, int timeout);


void IR_Receiver_cancel(IR_Receiver_t *irrecv);


#endif
