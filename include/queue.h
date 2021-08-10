#ifndef QUEUE_H
#define QUEUE_H

#include <stdlib.h>

typedef struct queue_list{
    int size;
    int qp;
    short *data;
}queue;

queue *init_queue(int);

int isEmpty(queue *);

int isFull(queue *);

int push(queue *, short);

short pop(queue *);

#endif
