#ifndef MEM_H
#define MEM_H

#include <pthread.h> /* pthread_t */
#include <stdlib.h> /* free(), malloc() */
#include <unistd.h> /* close() */
#include <string.h> /* strncmp() */
#include <stdio.h>

#define PTR_ID_SIZ 26

typedef struct pointer_list{
    struct pointer_list *prev;
    void *ptr;
    short size;
    char id[PTR_ID_SIZ]; // 25 bytes for string + null byte 
    struct pointer_list *next;
} pointer_l;

/* data pool that can be accessed by all functions */
typedef struct data_pool{
    pthread_t recv_thread;
    pthread_t write_thread;
    int recv_fd;   /* - so we can properly close the */
    int write_fd;  /*   descriptors when aborting the scan */
    int allocations; /* - The number of memory regions currently allocated */
    int allocated; /* amount of memory in bytes that is in use */
    int freed; /* the amount of memory in bytes that is no longer in use */
    pointer_l *ptrs; /* - any memory allocations we have made that have */
} pool_d;            /*   not been freed. excluding the pool itself */

void clean_exit(pool_d *, int);

void *create_pool(pool_d *);

void *add_allocation(pool_d *, void *, short, char *);

int get_ptr_index(pointer_l *, void *);

int get_id_index(pointer_l *, char *);

pointer_l *ptr_via_index(pointer_l *, void *);

pointer_l *ptr_via_id(pointer_l *, char *);

void display_ptrs(pool_d *);

int remove_allocation(pool_d *, int);

void free_ptr_list(pointer_l *);

#endif
