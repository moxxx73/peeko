#include "../include/osx_net.h"

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