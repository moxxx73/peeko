#include "raw_engine.h"

extern results_d *results;

/* just a wrapper function for now... */
int *open_recvr(char *ifn, int timeout){
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

int open_writer(int family, int protocol){
    int fd, y=1;
    fd = socket(family, SOCK_RAW, protocol);
    if(fd < 0) return -1;
    if(setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &y, sizeof(y)) < 0){
        close(fd);
        return -1;
    }
    return fd;
}

/* again, another wrapper function... */
int set_filter(int fd, filter_data *d){
    int r;
    r = setFilter(fd, d);
    return r;
}

int sniff(int fd, int blen, int timeout, int method){
    struct bpfData *data;
    int count = 0;
    if((data = read_descriptor(fd, blen)) == NULL){
        return 0;
    }
    count = getLength(data);
    port_state_bpf(data, method);
    trashAll(data);
    return count;
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

void port_state_bpf(struct bpfData *data, int method){
    struct bpfData *p = data;
    char *pkt;
    short sport;
    int state;
    while(p != NULL){
        pkt = p->data;
        if(pkt == NULL){
            p = p->nxt;
            continue;
        }
        state = _state(pkt, method);
        if(state > 0){
            sport = get_sport(pkt);
            add_sport(results, sport);
        }
        p = p->nxt;
    }
    return;
}

short *add_sport(results_d *r, short port){
    short *new;
    int new_sz = r->size+1;
    new = realloc(r->open_ports, new_sz);
    if(new == NULL) return NULL;
    new[r->size] = port;
    r->size = new_sz;
    r->open_ports = new;
    return new;
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
