#ifndef RAW_H
#define RAW_H

#include "bpf.h"
#include "queue.h"
#include "raw_net.h"
#include <netinet/tcp.h> /*struct tcphdr, TH_SYN, ...*/
#include <sys/socket.h> /* AF_INET, socket() */
#include <netinet/in.h> /* IPPROTO_IP, ...*/

#define ETHSIZ 14
#define IPSIZ 20
#define TCPSIZ 20

/* defined here for now, might do some moving around later idk*/
#define SYN_METH 1
#define TCP_CON 0

typedef struct sniffer_struct{
    int fd;
    int blen;
    int jobs;
    int method;
    int timeout;
} sniffer_d;

typedef struct writer_struct{
    int fd;
    unsigned int dst;
    unsigned int src;
    short id;
    short sport;
    queue *q;
    int method;
} writer_d;

typedef struct scan_results{
    int packets_recvd;
    int dropped;
    int packets_sent;
    int size;
    short *open_ports;
} results_d;

int *open_recvr(char *, int);

int open_writer(int, int);

int set_filter(int, filter_data *);

int sniff(int, int, int, int);

struct bpfData *read_descriptor(int, int);

void port_state_bpf(struct bpfData *, int);

short *add_sport(results_d *, short);

int _state(char *, int);

#endif
