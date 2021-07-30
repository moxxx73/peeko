#include "scan.h"

extern char verbose;
extern char debug;
extern char paralell;

pthread_mutex_t lock;

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

void portState(char *packet){
    struct tcphdr *tcp;
    tcp = (struct tcphdr *)(packet+ETH_SIZE+IP_SIZE);
    if(tcp->th_flags == (TH_SYN|TH_ACK)){
        if(paralell) pthread_mutex_lock(&lock);
        printf("\tPort %hu is open\n", ntohs(tcp->th_sport));
        if(paralell) pthread_mutex_unlock(&lock);
    }
    return;
}

int *init_scan(char *ifn){
    int r, w, blen;
    int *ret;
    w = write_socket(AF_INET, IPPROTO_IP);
    if(w < 0){
        printf("[!] write_socket(): %s\n", strerror(errno));
        return NULL;
    }
    r = openDev();
    if(r < 0){
        printf("[!] openDev(): %s\n", strerror(errno));
        return NULL;
    }
    blen = setAll(r, ifn);
    if(blen < 0){
        printf("[!] setAll(): %s\n", strerror(errno));
        return NULL;
    }
    if(debug) printf("\t\t[Debug] Opened /dev/bpf (Buffer: %d)\n", blen);
    ret = (int *)malloc(sizeof(int)*3);
    if(ret != NULL){
        ret[0] = w;
        ret[1] = r;
        ret[2] = blen;
        return ret;
    }
    return NULL;
}

short response(int fd, packet_d *data, int blen){
    struct bpfData *packets;
    int *r, bytes, count = 0, index = -1;
    char *packet;
    packets = initList();
    if(packets == NULL){
        return 0;
    }
    bytes = readDev(fd, packets, blen);
    //if(b > 0) printf("[+] Read %d packet(s)\n", count);
    r = find_rfh(packets, data);
    if(r != NULL){
        /*if(debug == 1){
            printf("\t\t[Debug] Got %d Response(s)\n", r[0]);
            printf("\t\t[Debug] First response at index %d\n", r[1]);
        }*/
        count = r[0];
        index = r[1];
        if(count == 0){
            free(r);
            return count;
        }
        packet = (char*)getData(packets, index);
        if(debug) printf("\t\t[Debug] Response packet @ %p\n", (void *)packet);
        portState(packet);
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
int single_port(int w, int r, int blen, scan_a *args){
    int ret;
    char *packet = NULL;
    packet_d *data = NULL;

    data = (packet_d *)malloc(sizeof(packet_d));
    if(data == NULL){
        if(paralell) pthread_mutex_lock(&lock);
        printf("[!] Failed to allocate %lu bytes of memory\n", sizeof(packet_d));
        if(paralell) pthread_mutex_unlock(&lock);
        return -1;
    }
    data->src = args->src;
    data->dst = args->dst;
    data->sport = args->sport;
    data->dport = args->daport;
    data->id = args->id;
    packet = buildPacket(packet, data, SYN_METH);
    if(packet == NULL){
        if(paralell) pthread_mutex_lock(&lock);
        printf("[!] Failed to create packet\n");
        if(paralell) pthread_mutex_unlock(&lock);
        return -1;
    }
    /* no need to call pthread_mutex_lock() as each thread has their own */
    /* pair of file descriptors */
    ret = sendData(w, data, packet, SYNSIZ);
    if(ret < 0){
        if(paralell) pthread_mutex_lock(&lock);
        printf("[!] sendData(): %s\n", strerror(errno));
        if(paralell) pthread_mutex_unlock(&lock);
    }

    /* i shouldn't have to worry about this debug text when single_port() */
    /* is called by a thread. check cafebabe.c:70 */
    if(debug) printf("\t\t[Debug] Wrote %d bytes to socket\n", ret);
    ret = response(r, data, blen);
    return 0;
}

void *do_jobs(void *ptr){
    thread_a *packed;
    scan_a *args;
    int i, w, r, blen, *ret_ptr;
    packed = (thread_a *)(ptr);
    args = &packed->args;

    ret_ptr = init_scan(args->ifn);
    if(ret_ptr == NULL){
        if(paralell) pthread_mutex_lock(&lock);
        printf("[!] init_scan(): %s\n", strerror(errno));
        if(paralell) pthread_mutex_unlock(&lock);
        return NULL;
    }
    w = ret_ptr[0];
    r = ret_ptr[1];
    blen = ret_ptr[2];
    free(ret_ptr);

    i = args->daport;
    for(;i!=packed->dbport;i++){
        args->daport = i;
        single_port(w, r, blen, args);
    }
    /*pthread_mutex_lock(&lock);
    printf("Pool[%d] - %hu\n", packed->tid, packed->dbport);
    pthread_mutex_unlock(&lock);*/
    close(w);
    close(r);
    return NULL;
}

void init_threads(scan_a *args, short dbport, int t, int jpt, int rm){
    pthread_t pool[t];
    thread_a **ptr;
    int i;
    short cport;
    cport = args->daport;
    ptr = (thread_a **)malloc(sizeof(thread_a *)*t);
    for(i=0;i<t;i++){
        ptr[i] = (thread_a *)malloc(sizeof(thread_a));
        memcpy(&ptr[i]->args, args, sizeof(scan_a));
        ptr[i]->args.daport = cport;
        ptr[i]->dbport = cport+(short)jpt;
        ptr[i]->tid = i;
        /* Give the remaining jobs to the last thread */
        if(i == (t-1)){
            ptr[i]->dbport += (short)rm;
        }
        pthread_create(&pool[i], NULL, do_jobs, (void *)ptr[i]);
        cport += (short)jpt;

    }
    for(i=0;i<t;i++){
        pthread_join(pool[i], NULL);
        free(ptr[i]);
    }
    free(ptr);
    return;
}
