#ifndef QUEUE_H
#define QUEUE_H

#include <stdlib.h>

/* so even tho i called this section of code "queue" its practically */
/* a stack but we can pretend that its a queue using a filo system */

typedef struct queue_list{
    int size;
    int qp;
    short *data;
}queue;

/* creates a queue head (the struct above)*/
queue *init_queue(int);

/* returns 1 if the queue is empty, 0 if its not */
int isEmpty(queue *);

/* same as above but for yknow, if its full */
int isFull(queue *);

/* add data to the "queue" */
int push(queue *, short);

/* remove the top item on the "queue" */
short pop(queue *);

#endif
