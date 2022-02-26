#ifndef RESULTS_H
#define RESULTS_H

#include <stdlib.h>
#include <stdio.h>
#include "utils.h"

typedef struct scan_results{
    char *ip_string;
    int packets_recvd;
    short number_of_open;
    short *open_ports;
} results_d;

#define RESULTS_SIZ sizeof(results_d)
#define RESULTS_TAG "results_struct\0"

results_d *init_results(void);

int add_open_port(results_d *, short);

void display_results(results_d *);

#endif
