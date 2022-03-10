#ifndef RAW_H
#define RAW_H

#include <string.h>
#include <net/if.h>

#include "linux_net.h"
#include "utils.h"
#include "memory.h"
#include "stack.h"
#include "packets.h"

/* main data structure used for raw scans */
typedef struct raw_scan_data{
    char interface_name[IF_NAMESIZE]; /* name of the working interface */
    unsigned int src_ip; /* source IPv4 address */
    unsigned int dst_ip; /* destination IPv4 address */
    int family; /* socket family (AF_INET/AF_INET6)*/
    short sport; /* source TCP port */
    stack *dports; /* stack containing ports to be scanned */
    short scan_flags; /* flags used in transmission */
    short open_flags; /* flags indicating a positive test case */
} scan_data;
#define SCAN_DATA_SIZ sizeof(scan_data)

/* allocates a packet and sets the IPv4 and TCP fields */
char *construct_packet(scan_data *data, char peek_flag);

/* parse responses and determine whether provided flags match with positive_flag */
int parse_packet(char *packet, int packet_length, short positive_flag, int tun);

#endif
