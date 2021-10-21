#ifndef CAFEBABE_H
#define CAFEBABE_H

#include <stdio.h>
#include <stdlib.h> /* free(), malloc() */
#include <string.h> /* memcpy() */
#include <pthread.h>
#include <signal.h>

#include "stack.h"
#include "scan.h"
#include "memory.h"
#include "utils.h"

typedef struct function_args{
    char *addr;
    char *ifn;
    short sport;
    int method;
    int timeout;
} cafebabe;

#define CAFEBABE_SIZ sizeof(cafebabe)
#define CAFEBABE_TAG "cafebabe_args\0"

/* just the "main" function that'll probs branch off */
void cafebabe_main(cafebabe *, char*, parse_r *, int);

#endif
