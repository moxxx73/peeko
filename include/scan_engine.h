#ifndef RECV_H
#define RECV_H

#include <errno.h>
#include <stdio.h>
#include <stdlib.h> /* malloc(), free() */
#include <unistd.h> /* close() */
#include <string.h> /* strerror() */
#include <pthread.h>

#include "raw_engine.h"
#include "queue.h"

/* defined here for now, might move em later idk*/
#define SYN_METH 1
#define TCP_CON 0

typedef struct sniffer_args{
    unsigned int src;
    unsigned int dst;
    short sport;
    queue *q;
    char *ifn;
    char method;
} scan_p;

int start_sniffer(scan_p *);

void *sniffer(void *);

void signal_handler(int);

#endif
