#include "low_net.h"

extern results_d *results;
extern char verbose;

/* just a wrapper function for now... */
int *open_recvr(char *ifn, int timeout, int family){
    int *r=NULL;
    r = (int *)malloc(sizeof(int)*2);
    if(r == NULL) return NULL;
    #if __APPLE__
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
    #else
        struct ifreq ifr;
        struct timeval tm;
        memcpy(&ifr, ifn, IFNAMSIZ);
        r[0] = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if(r[0] < 0){
            free(r);
            return NULL;
        }
        if(setsockopt(r[0], SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0){
            close(r[0]);
            free(r);
            return NULL;
        }
        tm.tv_usec = 0;
        tm.tv_sec = timeout;
        if(setsockopt(r[0], SOL_SOCKET, SO_RCVTIMEO, &tm, sizeof(tm)) < 0){
            close(r[0]);
            free(r);
            return NULL;
        }
        r[1] = 4096;
    #endif
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

int sniff(int fd, int blen, int timeout, int method){
    #if __APPLE__
        struct bpfData *data;
        int count = 0;
        if((data = read_dev(fd, blen)) == NULL){
            return 0;
        }
        count = getLength(data);
        port_state_bpf(data, method);
        trashAll(data);
        return count;
    #else
        return 0;
    #endif
}

#if __APPLE__
struct bpfData *read_dev(int fd, int blen){
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
    while(p->nxt != NULL){
        pkt = p->data;
        if(pkt == NULL){
            p = p->nxt;
            continue;
        }
        state = _state(pkt, method);
        if(state > 0){
            sport = get_sport(pkt);
            if(verbose) printf("    + Port %hu is open\n", sport);
            add_sport(results, sport);
        }
        p = p->nxt;
    }
    return;
}

#else

int read_sock(int s, int read_size, int method){
    char *packet_buf;
    int r;

    packet_buf = (char *)malloc(read_size);
    if(!packet_buf){
        return -1;
    }
    r = recvfrom(s, packet_buf, read_size, 0, NULL, NULL);
    //parse_packet(packet_buf, method, results);
    return r;
}

#endif