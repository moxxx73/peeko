#ifndef MEM_H
#define MEM_H

#include <pthread.h> /* pthread_t */
#include <stdlib.h> /* free(), malloc() */
#include <unistd.h> /* close() */
#include <stdio.h>

typedef struct pointer_list{
    struct pointer_list *prev;
    void *ptr;
    struct pointer_list *next;
} pointer_l;

/* memory pool that can be accessed by all functions */
typedef struct data_pool{
    pthread_t recv_thread;
    pthread_t write_thread;
    int recv_fd;   /* - so we can properly close the */
    int write_fd;  /*   descriptors when aborting the scan */
    int allocations; /* - The number of memory regions currently allocated */
    pointer_l *ptrs; /* - any memory allocations we have made that have */
} pool_d;            /*   not been freed. excluding the pool itself */

void clean(pool_d *);

void *create_pool(pool_d *);

void *add_allocation(pointer_l *, void *);

int get_ptr_index(pointer_l *, void *);

void display_ptrs(pointer_l *);

int remove_allocation(pointer_l *, int);

void free_ptr_list(pointer_l *);

#endif
