#include <unistd.h> /* close() */
#include <stdlib.h> /* malloc(), free() */
#include <stdio.h>
#include <sys/socket.h> /* socket(), AF_INET, ...*/
#include <netinet/in.h> /* IPPROTO_IP, ... */
#include <string.h> /* strerror() */
#include <errno.h> /* errno */

#include "bpf.h"
#include "framez.h"

/* use this instead of providing loads of arguments */
typedef struct scanArgs{
    char *ifn;
    unsigned long src;
    unsigned long dst;
    short sport;
    short daport;
    short dbport;
    short id;
    char verbose;
} scan_a;

/* sure, i could just create a ethernet frame when */
/* writing to /dev/bpf or i could just open a regular */
/* raw socket */
int write_socket(int, int);

/* could i combine the read/write functions */
/* to send a packet and simultaneously read */
/* /dev/bpf looking for the response? */

/* just a wrapper for sendto */
int sendData(int, packet_d *, char *, int);

/* Just probes a single port */
int single_port(scan_a *);
