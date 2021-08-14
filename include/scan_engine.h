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

typedef struct sniffer_args{
    unsigned int src;
    unsigned int dst;
    short sport;
    queue *q;
    char *ifn;
    char method;
    int timeout;
} scan_p;

typedef struct scan_results{
    int packets_recvd;
    int dropped;
    int packets_sent;
    int size;
    short *open_ports;
} results_d;

int start_sniffer(scan_p *);

void *sniffer(void *);

int sniff(int, int, int, int);

void port_state_bpf(struct bpfData *, int);

void signal_handler(int);

#endif
