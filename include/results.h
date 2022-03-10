#ifndef RESULTS_H
#define RESULTS_H

#include <stdlib.h>
#include <stdio.h>
#include "utils.h"

/* results struct containing data about the scan */
typedef struct scan_results{
    char *ip_string;
    int packets_recvd;
    short number_of_open;
    short *open_ports;
} results_d;

#define RESULTS_SIZ sizeof(results_d)

/* allocate and initialise result struct */
results_d *init_results(void);

/* append an open port to the open_ports array */
int add_open_port(results_d *, short);

/* displays open ports at the end of the scan */
void display_results(results_d *);

#endif
