#include "stack.h"

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
