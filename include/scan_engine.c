#include "scan_engine.h"

#include "memory.h"

extern char debug;
extern char underline[];
extern char reset[];

extern pool_d *pool;

int start_sniffer(scan_p *recv_p){
    filter_data *f_data;
    sniffer_d *sniff_d;
    int fd;
    int blen;
    int *r, index;
    f_data = (filter_data *)malloc(sizeof(filter_data));
    if(f_data == NULL){
        printf("Failed to allocate bpf_filter structure\n");
        clean_exit(pool);
    }
    f_data->src = recv_p->src;
    f_data->dst = recv_p->dst;
    if(debug){
        printf("\t\t%s[DEBUG]%s Allocated bpf_filter @ %p\n", underline, reset, (void *)f_data);
        printf("\t\t        Source: 0x%04x\n", f_data->dst);
        printf("\t\t        Destination: 0x%04x\n", f_data->src);
    }
    add_allocation(pool->ptrs, (void *)f_data);
    if((r = open_descriptor(recv_p->ifn)) == NULL){
        printf("Failed to open descriptor: %s\n", strerror(errno));
        clean_exit(pool);
    }
    fd = r[0];
    pool->recv_fd = fd;
    blen = r[1];
    free(r);
    if(debug) printf("\t\t%s[DEBUG]%s Opened BPF device (Descriptor: %d[Buffer length: %d])\n", underline, reset, fd, blen);
    //if(debug) printf("\t\t%s[DEBUG]%s Calling set_filter (%p)\n", underline, reset, (void *)&set_filter);
    if(set_filter(fd, f_data) < 0){
        printf("Failed to set filter: %s\n", strerror(errno));
    }
    index = get_ptr_index(pool->ptrs, (void *)f_data);
    remove_allocation(pool->ptrs, index);
    free(f_data);
    if((sniff_d = (sniffer_d *)malloc(sizeof(sniffer_d))) == NULL){
        printf("Failed to allocate sniffer_d structure\n");
        clean_exit(pool);
    }
    sniff_d->fd = fd;
    sniff_d->blen = blen;
    sniff_d->method = recv_p->method;
    add_allocation(pool->ptrs, (void *)sniff_d);
    pthread_create(&pool->recv_thread, NULL, sniffer, (void *)sniff_d);
    return 0;
}

void *sniffer(void *data){
    sniffer_d *args = (sniffer_d *)data;
    return NULL;
}

void signal_handler(int signal){
    printf("\nCaught Interrupt...\n");
    pool->terminate = 1;
    clean_exit(pool);
    return;
}
