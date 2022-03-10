#ifndef MEM_H
#define MEM_H

#include <stdlib.h> /* free(), malloc() */
#include <unistd.h> /* close() */
#include <string.h> /* strncmp() */
#include <stdio.h>
#include <sys/mman.h>
#include <net/if.h>

#include "stack.h"
#include "results.h"

/* double linked list containing allocation metadata */
typedef struct ptr_listist{
    struct ptr_listist *prev;
    void *ptr;
    short size;
    struct ptr_listist *next;
} ptr_list;

/* memory structure storing any allocations, */
/* allocation metatdata and file descriptors */
typedef struct mem_data{
    int rx_ring_size;
    void *rx_ring;
    int recv_fd;
    int write_fd; 
    int allocations; 
    int allocated; 
    int freed; 
    ptr_list *ptrs; 
} mem_obj; 

/* wrapper around exit() that ensures that file      */
/* descriptors are closed and all memory allocations */
/* made are properly freed                           */
void clean_exit(mem_obj *, int);

/* allocates the mem_obj structure */
mem_obj *alloc_mem_obj(mem_obj *);

/* append a new allocation to the double linked list */
void *add_allocation(mem_obj *, void *, short);

/* returns a pointers index in the linked list */
int get_ptr_index(ptr_list *, void *);

int remove_allocation(mem_obj *, int);

void free_ptr_list(ptr_list *);

void display_stats(mem_obj *);
#endif

