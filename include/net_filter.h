#ifndef FILTER_H
#define FILTER_H

#include <linux/bpf_common.h>
#include <linux/filter.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>

#include "utils.h"

/* the only packets we're interested in are ones        */
/* responding to our transmissions and the raw socket   */
/* receives alot of data that isnt relevant to our scan */
/* so it helps to cut down on the noise we capture      */
typedef struct filter_data_struct{
	unsigned int src; /* Targets IPv4 address */
	unsigned int dst; /* our IPv4 address */
    short dport; /* our transmitting TCP port */
} filter_data;

/* sets socket filter */
int set_filter(int fd, filter_data *ptr, int tun);

#endif
