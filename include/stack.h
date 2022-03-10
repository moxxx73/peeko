#ifndef STACK_H
#define STACK_H
#include <stdlib.h>
#include <string.h>

/* self explanatory struct */
typedef struct stack_header{
    int frame_size;
    short *stack_frame;
    int sp; /* stack pointer */
} stack;
#define STACK_HDR_SIZ sizeof(stack)

/* allocates and initiliases the stack header */
stack *alloc_stack(int size);

/* push a short (2 byte integer/word) onto the stack*/
char push(stack *hdr, short val);

/* returns true (1) if the stack is full */
char stack_full(stack *);

/* returns true (1) if the stack is empty */
char stack_empty(stack *);

/* pop (remove) a value from the stack */
short pop(stack *);

/* return the last value on the stack without */
/* decrementing the stack pointer             */
short peek(stack *);

#endif
