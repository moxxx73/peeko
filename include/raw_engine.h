#ifndef RAW_H
#define RAW_H

#include "bpf.h"
#include <netinet/tcp.h>

#define ETHSIZ 14
#define IPSIZ 20

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

int *open_descriptor(char *, int);

int set_filter(int, filter_data *);

struct bpfData *read_descriptor(int, int);

int _state(char *, int);

#endif
