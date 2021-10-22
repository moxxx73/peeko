#ifndef RESULTS_H
#define RESULTS_H

#include <stdlib.h>
#include <stdio.h>

typedef struct scan_results{
    int packets_recvd;
    int dropped;
    int packets_sent;
    short number_of_open;
    short number_of_closed;
    short *open_ports;
    short *closed_ports;
} results_d;

#define RESULTS_SIZ sizeof(results_d)
#define RESULTS_TAG "results_struct\0"

results_d *init_results();

int add_open_port(results_d *, short);

int add_closed_port(results_d *, short);

void display_results(results_d *);

void asc_sort(void);

void desc_sort(void);

#endif