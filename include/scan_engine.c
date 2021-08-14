#include "scan_engine.h"

#include "memory.h"

extern char debug;
extern char underline[];
extern char reset[];

extern pool_d *pool;
extern results_d *results;

int start_sniffer(scan_p *recv_p){
    filter_data *f_data;
    sniffer_d *sniff_d;
    int fd;
    int blen;
    int *r, index;
    f_data = (filter_data *)malloc(sizeof(filter_data));
    if(f_data == NULL){
        printf("Failed to allocate bpf_filter structure\n");
        clean(pool);
        exit(1);
    }
    f_data->src = recv_p->src;
    f_data->dst = recv_p->dst;
    if(debug){
        printf("%s[DEBUG]%s Allocated bpf_filter @ %p\n", underline, reset, (void *)f_data);
        printf("        Source: 0x%04x\n", f_data->dst);
        printf("        Destination: 0x%04x\n", f_data->src);
    }
    add_allocation(pool->ptrs, (void *)f_data);
    if((r = open_descriptor(recv_p->ifn, recv_p->timeout)) == NULL){
        printf("Failed to open descriptor: %s\n", strerror(errno));
        clean(pool);
        exit(1);
    }
    fd = r[0];
    pool->recv_fd = fd;
    blen = r[1];
    free(r);
    if(debug) printf("%s[DEBUG]%s Opened BPF device (Descriptor: %d[Buffer length: %d])\n", underline, reset, fd, blen);
    //if(debug) printf("\t\t%s[DEBUG]%s Calling set_filter (%p)\n", underline, reset, (void *)&set_filter);
    if(set_filter(fd, f_data) < 0){
        printf("Failed to set filter: %s\n", strerror(errno));
        clean(pool);
        exit(1);
    }
    index = get_ptr_index(pool->ptrs, (void *)f_data);
    remove_allocation(pool->ptrs, index);
    free(f_data);
    if((sniff_d = (sniffer_d *)malloc(sizeof(sniffer_d))) == NULL){
        printf("Failed to allocate sniffer_d structure\n");
        clean(pool);
        exit(1);
    }
    sniff_d->fd = fd;
    sniff_d->blen = blen;
    sniff_d->jobs = recv_p->q->size;
    sniff_d->method = recv_p->method;
    sniff_d->timeout = recv_p->timeout;
    add_allocation(pool->ptrs, (void *)sniff_d);
    pthread_create(&pool->recv_thread, NULL, sniffer, (void *)sniff_d);
    return 0;
}

void *sniffer(void *data){
    sniffer_d *args = (sniffer_d *)data;
    int responses=0, new=0, retries=0;
    int expected_responses;
    expected_responses = args->jobs;
    while((responses != expected_responses)){
        if(retries == 5) break;
        new = sniff(args->fd, args->blen, (args->timeout*1000), SYN_METH);
        if(new == 0) retries += 1;
        responses += new;
    }
    return NULL;
}

void port_state_bpf(struct bpfData *data, int method){
    struct bpfData *p = data;
    char *pkt;
    int state;
    while(p != NULL){
        pkt = p->data;
        if(pkt == NULL){
            p = p->nxt;
            continue;
        }
        state = _state(pkt, method);
        p = p->nxt;
    }
    return;
}

int sniff(int fd, int blen, int timeout, int method){
    struct bpfData *data;
    int count = 0;
    if((data = read_descriptor(fd, blen)) == NULL){
        return 0;
    }
    count = getLength(data);
    //printf("%d\n", count);
    port_state_bpf(data, method);
    trashAll(data);
    return count;
}

void signal_handler(int signal){
    printf("\nCaught Interrupt...\n");
    clean(pool);
    exit(130);
}
