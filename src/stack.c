#include "../include/stack.h"

stack *alloc_stack(int size){
    stack *r = NULL;
    r = (stack *)malloc(STACK_HDR_SIZ);
    if(!r) return NULL;
    r->frame_size = size;
    r->sp = -1;
    r->stack_frame = (short *)malloc((sizeof(short)*size));
    if(!r->stack_frame){
        free(r);
        return NULL;
    }
    memset((void *)r->stack_frame, 0, (sizeof(short)*size));
    return r;
}

char stack_full(stack *hdr){
    if(hdr->sp == (hdr->frame_size)) return 1;
    return 0;
}

char stack_empty(stack *hdr){
    if(hdr->sp == -1) return 1;
    return 0;
}

char push(stack *hdr, short val){
    if(stack_full(hdr)) return -1;
    hdr->stack_frame[++hdr->sp] = val; 
    return 0;
}

short pop(stack *hdr){
    if(stack_empty(hdr)) return -1;
    return hdr->stack_frame[hdr->sp--]; 
}

short peek(stack *hdr){
    return hdr->stack_frame[hdr->sp];
}