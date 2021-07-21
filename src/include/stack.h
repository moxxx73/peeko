#ifndef STACK_H
#define STACK_H

#include <stdlib.h> /* malloc(), free() */

/* Stack data structure */
typedef struct stackStructure{
    int capacity;
    int sp;
    int *data;
} stack;

/* Initialse the stack */
stack *init_stack(int);

/* checks whether the stack is full */
int isFull(stack *);

/* checks whether the stack is empty */
int isEmpty(stack *);

/* push data to the top of the stack */
int push(stack *, int);

/* remove and return the data at the top of the stack */
int pop(stack *);

/* return the data at the top of the stack */
int peek(stack *);
#endif
