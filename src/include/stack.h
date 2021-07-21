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
