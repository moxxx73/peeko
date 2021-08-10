#ifndef RAW_H
#define RAW_H

#include "bpf.h"

typedef struct sniffer_struct{
    int fd;
    int blen;
    int method;
} sniffer_d;

int *open_descriptor(char *);

int set_filter(int, filter_data *);

int read_descriptor(int, int);

#endif
