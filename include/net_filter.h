#ifndef FILTER_H
#define FILTER_H

#include <linux/bpf_common.h>
#include <linux/filter.h>
#include <netinet/in.h> /* IPPROTO_TCP */
#include <arpa/inet.h> /* htonl(), ... */
#include <stdlib.h>

#include "utils.h"

/* the data that has to be in apacket for it to */
/* pass thru the filter */
typedef struct filter_data_struct{
	unsigned int src;
	unsigned int dst;
	short dport;
    short sport;
} filter_data;

int set_filter(int fd, filter_data *ptr, int tun);

#endif
