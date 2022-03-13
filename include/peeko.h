#ifndef PEEKO_H
#define PEEKO_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "stack.h"
#include "scan.h"
#include "memory.h"
#include "utils.h"

/* the main purpose of this struct is to */
/* keep the amount of function variables */
/* passed to peeko_main low, im also  */
/* kind of addicted to structs           */
typedef struct function_args{
    char *addr; /* Hostname/IP address of the target (ASCII) */
    char *ifn;  /* The name of the wokring interface */
    short sport; /* Source Port */ 
    int method; /* Selected scan method */
    int timeout; /* Timeout for socket operations */
} peeko_obj;
#define PEEKO_OBJ_SIZE sizeof(peeko_obj)

/* moves ports from a list (lst) to a stack (st) */
int fill_stack(parse_r *lst, stack *st);

/* handles SIGINT cleanly */
void signal_handler(int signal);

/* the "main" function that allocates necessary data structures */
void peeko_main(peeko_obj *args, char *name, parse_r *lst, char resolve);

#endif

