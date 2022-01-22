#ifndef RAW_H
#define RAW_H

#if __APPLE__
    #include "net_osx.h"
#else
    #include "linux_net.h"
#endif

#include "utils.h"
#include "memory.h"
#include "stack.h"
#include "packets.h"

#include <string.h>
#include <net/if.h>

/* global structure for recording all relevant info */
/* regarding the scan job */
typedef struct raw_scan_data{
    char interface_name[IF_NAMESIZE];
    unsigned int src_ip;
    unsigned int dst_ip;
    int family;
    int thread_c;
    short sport;
    stack *dports;
    short scan_flags;
    short open_flags;
} scan_data;

#define SCAN_DATA_SIZ sizeof(scan_data)
#define SCAN_DATA_TAG "raw_scan_data\0"

char *construct_packet(scan_data *data, char peek_flag);

int parse_packet(char *packet, int packet_length, short positive_flag);
#endif
