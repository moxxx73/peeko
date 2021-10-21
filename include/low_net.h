#ifndef RAW_H
#define RAW_H

#if __APPLE__
    #include "bpf.h"
#else
    #include <net/if.h> /* struct ifreq, ... */
    #include <sys/time.h>
#endif

#include "stack.h"
#include "packets.h"
#include "results.h"
#include "net_filter.h"
#include <unistd.h>
#include <netinet/tcp.h> /*struct tcphdr, TH_SYN, ... */
#include <sys/socket.h> /* AF_INET, socket() */
#include <netinet/in.h> /* IPPROTO_IP, ... */

/* defined here for now, might do some moving around later idk*/
#define SYNCHRONISE_SCAN 0x0002

typedef struct sniffer_struct{
    int fd;
    int blen;
    int jobs;
    int method;
    int timeout;
} sniffer_d;

#define RECV_A_SIZ sizeof(sniffer_d)

typedef struct writer_struct{
    int fd;
    unsigned int dst;
    unsigned int src;
    short id;
    short sport;
    stack *st;
    int method;
} writer_d;

#define WRITE_A_SIZ sizeof(writer_d)

int *open_recvr(char *, int, int);

int open_writer(int, int);

int sniff(int, int, int, int);

#if __APPLE__
struct bpfData *read_dev(int, int);

void port_state_bpf(struct bpfData *, int);
#endif

#endif
