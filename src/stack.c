#include "../include/stack.h"

/* allocates and initiliases the stack header */
stack *alloc_stack(int size){
    stack *r = NULL;
    r = (stack *)malloc(STACK_HDR_SIZ);
    if(!r) return NULL;
    /* initialise stack header data to avoid */
    /* erroneous behaviour                   */
    r->frame_size = size;
    r->sp = -1;
    r->stack_frame = (short *)malloc((sizeof(short)*size));
    if(!r->stack_frame){
        free(r);
        return NULL;
    }
    /* zero out the allocated stack array as the allocated */
    /* area may have contained random junk data            */
    memset((void *)r->stack_frame, 0, (sizeof(short)*size));
    return r;
}

/* push a short (2 byte integer/word) onto the stack*/
char push(stack *hdr, short val){
    if(stack_full(hdr)) return -1;
    hdr->stack_frame[++hdr->sp] = val; 
    return 0;
}

/* returns true (1) if the stack is full */
char stack_full(stack *hdr){
    if(hdr->sp == (hdr->frame_size)) return 1;
    return 0;
}

/* returns true (1) if the stack is empty */
char stack_empty(stack *hdr){
    if(hdr->sp == -1) return 1;
    return 0;
}

/* pop (remove) a value from the stack */
short pop(stack *hdr){
    if(stack_empty(hdr)) return -1;
    return hdr->stack_frame[hdr->sp--]; 
}

/* return the last value on the stack without */
/* decrementing the stack pointer             */
short peek(stack *hdr){
    return hdr->stack_frame[hdr->sp];
}