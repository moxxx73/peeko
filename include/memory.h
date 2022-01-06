#ifndef MEM_H
#define MEM_H

#include <pthread.h> /* pthread_t */
#include <stdlib.h> /* free(), malloc() */
#include <unistd.h> /* close() */
#include <string.h> /* strncmp() */
#include <stdio.h>
#include <net/if.h>

#include "stack.h"

#define PTR_TAG_SIZ 26

typedef struct pointer_list{
    struct pointer_list *prev;
    void *ptr;
    short size;
    char tag[PTR_TAG_SIZ]; // 25 bytes for string + null byte 
    struct pointer_list *next;
} pointer_l;

/* data pool that can be accessed by all functions */
/* why use the term pool? cuz its makes stuff seem fancier */
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

/* incase any fatal errors occur we can exit */
/* safely (close descriptors and free allocated memory) */
void clean_exit(pool_d *, int);

/* just allocates the structure */
void *create_pool(pool_d *);

/* appends the pointer to a new memory allocation */
/* to the memory pools pointer list and updates */
/* memory data (e.g. amount allocated) */
void *add_allocation(pool_d *, void *, short, const char *);

int get_ptr_index(pointer_l *, void *);

int get_tag_index(pointer_l *, const char *);

pointer_l *ptr_via_index(pointer_l *, void *);

pointer_l *ptr_via_tag(pointer_l *, const char *);

int remove_allocation(pool_d *, int);

void free_ptr_list(pointer_l *);

void display_stats(pool_d *);
#endif
