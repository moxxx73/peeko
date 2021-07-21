#include "stack.h"

/* Initialise the stack */
stack *init_stack(int size){
	stack *ptr;
	ptr = (stack *)malloc(sizeof(stack));
	if(ptr == NULL){
		return NULL;
	}
	ptr->capacity = size;
	ptr->data = (int *)malloc(sizeof(int)*size);
	if(ptr->data == NULL){
		free(ptr);
		return NULL;
	}
	return ptr;
}

/* checks whether the stack is full */
int isFull(stack *p){
	return p->sp == p->capacity-1;
}

/* checks whether the stack is empty */
int isEmpty(stack *p){
	return p->sp == -1;
}

/* push data to the top of the stack */
int push(stack *p, int data){
	if(isFull(p)){
		return -1;
	}
	p->data[++p->sp] = data;
	return 0;
}

/* remove and return the data at the top of the stack */
int pop(stack *p){
        int data;
	if(isEmpty(p)){
		return -1;
	}
	data = p->data[p->sp--];
	return data;
}

/* return the data at the top of the stack */
int peek(stack *p){
	if(isEmpty(p)){
		return -1;
	}
	return p->data[p->sp];
}
