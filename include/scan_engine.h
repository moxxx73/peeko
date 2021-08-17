#ifndef RECV_H
#define RECV_H

#include <errno.h>
#include <stdio.h>
#include <stdlib.h> /* malloc(), free() */
#include <unistd.h> /* close() */
#include <string.h> /* strerror() */
#include <pthread.h>

#include "raw_engine.h"

typedef struct sniffer_args{
    unsigned int src;
    unsigned int dst;
    short sport;
    queue *q;
    char *ifn;
    char method;
    int timeout;
} scan_p;

int start_sniffer(scan_p *);

int start_writer(scan_p *, int);

void *writer(void *);

void *sniffer(void *);

void display_results(results_d *);

void signal_handler(int);

#endif
