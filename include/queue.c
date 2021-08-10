#include "queue.h"

queue *init_queue(int size){
    queue *ptr;
    ptr = (queue *)malloc(sizeof(queue));
    if(ptr != NULL){
        ptr->size = size;
        ptr->qp = -1;
        ptr->data = (short *)malloc(sizeof(short)*size);
        if(ptr->data != NULL) return ptr;
    }
    return NULL;
}

int isEmpty(queue *ptr){
    return ptr->qp == -1;
}

int isFull(queue *ptr){
    return ptr->qp == (ptr->size-1);
}

int push(queue *ptr, short job){
    if(isFull(ptr)) return -1;
    ptr->qp += 1;
    ptr->data[ptr->qp] = job;
    return 0;
}

short pop(queue *ptr){
    short value;
    if(isEmpty(ptr)) return 0;
    value = ptr->data[ptr->qp];
    ptr->qp -= 1;
    return value;
}
