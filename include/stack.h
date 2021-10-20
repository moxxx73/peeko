#ifndef STACK_H
#define STACK_H
#include <stdlib.h>
#include <string.h>

typedef struct stack_header{
    int frame_size;
    short *stack_frame;
    int sp;
} stack;

#define STACK_HDR_SIZ sizeof(stack)

stack *alloc_stack(int);

char push(stack *, short);

char stack_full(stack *);

char stack_empty(stack *);

short pop(stack *);

short peek(stack *);

#endif