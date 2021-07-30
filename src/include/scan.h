#include <unistd.h> /* close() */
#include <stdlib.h> /* malloc(), free() */
#include <stdio.h>
#include <sys/socket.h> /* socket(), AF_INET, ...*/
#include <netinet/in.h> /* IPPROTO_IP, ... */
#include <string.h> /* strerror() */
#include <errno.h> /* errno */
#include <pthread.h>

#include "bpf.h"
#include "framez.h"

/* use this instead of providing loads of arguments */
typedef struct scanArgs{
    char *ifn;
    unsigned int src;
    unsigned int dst;
    short sport;
    short daport;
    short id;
} scan_a;

typedef struct threadArgs{
    scan_a args;
    int dbport;
} thread_a;

/* sure, i could just create a ethernet frame when */
/* writing to /dev/bpf or i could just open a regular */
/* raw socket */
int write_socket(int, int);

/* used by find_rfh(), checks whether the packet is relevant */
int checkFrames(char *, packet_d *);

/* find any relevant packets in the provided bpfData */
/* linked list and returns the count */
int *find_rfh(struct bpfData *, packet_d *);

/* could i combine the read/write functions */
/* to send a packet and simultaneously read */
/* /dev/bpf looking for the response? */

void portState(char *);

short response(int, packet_d *, int);

/* just a wrapper for sendto */
int sendData(int, packet_d *, char *, int);

/* Just probes a single port */
int single_port(scan_a *);

void *do_jobs(void *ptr);

void init_threads(scan_a *, short, int, int, int);
