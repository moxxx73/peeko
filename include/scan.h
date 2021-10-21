#ifndef RECV_H
#define RECV_H

#include <errno.h>
#include <stdio.h>
#include <stdlib.h> /* malloc(), free() */
#include <unistd.h> /* close(), write() */
#include <string.h> /* strerror() */
#include <pthread.h>

#include "low_net.h"
#include "memory.h"

typedef struct scan_args{
    unsigned int src;
    unsigned int dst;
    short sport;
    stack *stk;
    char *ifn;
    char method;
    int family;
    int timeout;
} scan_p;

#define SCAN_SIZ sizeof(scan_p)
#define SCAN_ARGS_TAG "scan_args\0"

int start_sniffer(scan_p *);

int start_writer(scan_p *);

void *writer(void *);

void *sniffer(void *);

void signal_handler(int);

#endif
