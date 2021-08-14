#include "raw_engine.h"

/* just a wrapper function for now... */
int *open_descriptor(char *ifn, int timeout){
    int *r;
    r = (int *)malloc(sizeof(int)*2);
    if(r == NULL) return NULL;
    r[0] = openDev();
    if(r[0] < 0){
        free(r);
        return NULL;
    }
    r[1] = setAll(r[0], ifn, timeout);
    if(r[1] < 0){
        free(r);
        return NULL;
    }
    return r;
}

/* again, another wrapper function... */
int set_filter(int fd, filter_data *d){
    int r;
    r = setFilter(fd, d);
    return r;
}

struct bpfData *read_descriptor(int fd, int blen){
    struct bpfData *data;
    int count = 0;

    data = initList();
    if(data == NULL){
        trashAll(data);
        return NULL;
    }
    /* dunno what to do with this for now */
    count = readDev(fd, data, blen);
    return data;
}

int _state(char *packet, int method){
    /* filter only allows for ipv4+tcp packets */
    struct tcphdr *tcp = (struct tcphdr *)(packet+ETHSIZ+IPSIZ);
    switch(method){
        case SYN_METH:
            if(tcp->th_flags == (TH_SYN|TH_ACK)) return 1;
            break;
        default:
            return 0;
    }
    return 0;
}
