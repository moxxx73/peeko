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

typedef struct ptr_listist{
    struct ptr_listist *prev;
    void *ptr;
    short size;
    struct ptr_listist *next;
} ptr_list;

/* data pool that can be accessed by all functions */
/* why use the term pool? cuz its makes stuff seem fancier */
typedef struct mem_data{
    int rx_ring_size;
    void *rx_ring;
    int recv_fd;   /* - so we can properly close the */
    int write_fd;  /*   descriptors when aborting the scan */
    int allocations; /* - The number of memory regions currently allocated */
    int allocated; /* amount of memory in bytes that is in use */
    int freed; /* the amount of memory in bytes that is no longer in use */
    ptr_list *ptrs; /* - any memory allocations we have made that have */
} mem_obj;            /*   not been freed. excluding the pool itself */

/* incase any fatal errors occur we can exit */
/* safely (close descriptors and free allocated memory) */
void clean_exit(mem_obj *, int);

/* just allocates the structure */
mem_obj *alloc_mem_obj(mem_obj *);

/* appends the pointer to a new memory allocation */
/* to the memory pools pointer list and updates */
/* memory data (e.g. amount allocated) */
void *add_allocation(mem_obj *, void *, short);

int get_ptr_index(ptr_list *, void *);

ptr_list *ptr_via_index(ptr_list *, void *);

int remove_allocation(mem_obj *, int);

void free_ptr_list(ptr_list *);

void display_stats(mem_obj *);
#endif

