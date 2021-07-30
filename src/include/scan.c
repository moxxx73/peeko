#include "scan.h"

extern char verbose;
extern char debug;

/* now i could just use /dev/bpf but i have to also create the ethernet */
/* header which i just cannot be arsed doing atm */
int write_socket(int family, int protocol){
    int s, y=1;
    s = socket(family, SOCK_RAW, protocol);
    if(s < 0) return -1;
    /* yes ik, i give the option for the protocol but this call to setsockopt */
    /* is pretty set in stone, thats temporary ok? jeeez */
    if(setsockopt(s, IPPROTO_IP, IP_HDRINCL, &y, sizeof(y)) < 0) return -1;
    return s;
}

int checkFrames(char *data, packet_d *info){
    struct ip *iph;
    struct tcphdr *tcph;
    iph = (struct ip *)(data);
    if(iph->ip_src.s_addr == info->dst && iph->ip_dst.s_addr == info->src){
        if(iph->ip_p != IPPROTO_TCP) return -1;
        tcph = (struct tcphdr *)(data+IP_SIZE);
        if(ntohs(tcph->th_sport) != info->dport) return -1;
        return 0;
    }
    return -1;
}

/* looks for a response from the target in bpfData */
int *find_rfh(struct bpfData *p, packet_d *info){
    struct bpfData *c;
    struct ether_header *eth;
    int *r = NULL;
    int count = 0, index = -1, i = 0;
    c = p;
    r = (int *)malloc(sizeof(int)*2);
    if(r == NULL) return NULL;
    while(c != NULL){
        if(c->data != NULL){
            eth = (struct ether_header *)(c->data);
            if(ntohs(eth->ether_type) == ETHERTYPE_IP){
                if(checkFrames((c->data+ETH_SIZE), info) == 0){
                    if(index < 0) index = i;
                    count += 1;
                }
            }
        }
        i += 1;
        c = c->nxt;
    }
    r[0] = count;
    r[1] = index;
    return r;
}

short response(int fd, packet_d *data, int blen){
    struct bpfData *packets;
    int *r, bytes, count = 0;
    packets = initList();
    if(packets == NULL){
        return 0;
    }
    bytes = readDev(fd, packets, blen);
    //if(b > 0) printf("[+] Read %d packet(s)\n", count);
    r = find_rfh(packets, data);
    if(r != NULL){
        if(debug == 1){
            printf("\t\t[Debug] Got %d Response(s)\n", r[0]);
            printf("\t\t[Debug] First response at index %d\n", r[1]);
        }
        count = r[0];
        free(r);
    }
    trashAll(packets);
    return count;
}

/* Wrapper for that son of a bitch sendto() */
int sendData(int s, packet_d *data, char *packet, int size){
    struct sockaddr_in dst;
    int r;
    dst.sin_port = htons(data->dport);
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = data->dst;
    r = sendto(s, packet, size, 0, (struct sockaddr *)&dst, sizeof(struct sockaddr_in));
    return r;
}

/* not just for probing a single port but also for testing purposes */
int single_port(scan_a *args){
    int r, ret, w, blen;
    char *packet = NULL;
    packet_d *data = NULL;
    w = write_socket(AF_INET, IPPROTO_IP);
    if(w < 0){
        printf("[!] write_socket(): %s\n", strerror(errno));
        return -1;
    }
    r = openDev();
    if(r < 0){
        printf("[!] openDev(): %s\n", strerror(errno));
        return -1;
    }
    blen = setAll(r, args->ifn);
    if(blen < 0){
        printf("[!] setAll(): %s\n", strerror(errno));
        return -1;
    }
    if(verbose == 1) printf("\t[V] Opened /dev/bpf (Buffer: %d)\n", blen);
    data = (packet_d *)malloc(sizeof(packet_d));
    if(data == NULL){
        printf("[!] Failed to allocate %lu bytes of memory\n", sizeof(packet_d));
        return -1;
    }
    data->src = args->src;
    data->dst = args->dst;
    data->sport = args->sport;
    data->dport = args->daport;
    data->id = args->id;
    packet = buildPacket(packet, data, SYN_METH);
    if(packet == NULL){
        printf("[!] Failed to create packet\n");
        return -1;
    }
    ret = sendData(w, data, packet, SYNSIZ);
    if(ret < 0){
        printf("[!] sendData(): %s\n", strerror(errno));
    }
    if(debug == 1) printf("\t\t[Debug] Wrote %d bytes to socket\n", ret);
    if(response(r, data, blen) == 0){
            response(r, data, blen);
    };
    close(w);
    close(r);
    return 0;
}
