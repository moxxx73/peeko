#ifndef FILTER_H
#define FILTER_H

#if __APPLE__
    #include <net/bpf.h>
#else
    #include <linux/filter.h>
    #include <linux/bpf_common.h>
#endif

#include <netinet/in.h> /* IPPROTO_TCP */
#include <arpa/inet.h> /* htonl(), ... */

/* the data that has to be in apacket for it to */
/* pass thru the filter */
typedef struct filter_data_struct{
	unsigned int src;
	unsigned int dst;
	short dport;
    short sport;
} filter_data;

#define FILTER_SIZ sizeof(filter_data)
#define FILTER_TAG "filter_data\0"

int set_filter(int, filter_data *);

#endif