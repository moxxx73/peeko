#include "scan_engine.h"

#include "memory.h"

/*
extern char debug;
extern char underline[];
extern char reset[];
*/

extern pool_d *pool;
extern results_d *results;

char retry=0;

/* as of now there is no mutex locking as there are only two */
/* threads and they both have their own data structures to */
/* interact with */

int start_sniffer(scan_p *recv_p){
    filter_data *f_data;
    sniffer_d *sniff_d;
    int fd;
    int blen;
    int *r, index;
    /* change from previous iteration of project, without a filter applied */
    /* we struggle to pick up our response as it probably gets pushed back */
    /* by other packest picked up by the bpf device */
    f_data = (filter_data *)malloc(sizeof(filter_data));
    if(f_data == NULL){
        printf("Failed to allocate bpf_filter structure\n");
        clean_exit(pool, 1);
    }
    f_data->src = recv_p->src;
    f_data->dst = recv_p->dst;
    /*if(debug){
        printf("%s[DEBUG]%s Allocated bpf_filter @ %p\n", underline, reset, (void *)f_data);
        printf("        Source: 0x%04x\n", f_data->dst);
        printf("        Destination: 0x%04x\n", f_data->src);
    }*/
    add_allocation(pool->ptrs, (void *)f_data);
    if((r = open_recvr(recv_p->ifn, recv_p->timeout)) == NULL){
        printf("Failed to open descriptor: %s\n", strerror(errno));
        clean_exit(pool, 1);
    }
    fd = r[0];
    pool->recv_fd = fd;
    blen = r[1];
    free(r);
    /*if(debug){
        printf("%s[DEBUG]%s Opened BPF device (Descriptor: %d)\n", underline, reset, fd);
        printf("        Buffer length: %d\n", blen);
    }*/
    //if(debug) printf("\t\t%s[DEBUG]%s Calling set_filter (%p)\n", underline, reset, (void *)&set_filter);
    if(set_filter(fd, f_data) < 0){
        printf("Failed to set filter: %s\n", strerror(errno));
        clean_exit(pool, 1);
    }
    index = get_ptr_index(pool->ptrs, (void *)f_data);
    remove_allocation(pool->ptrs, index);
    free(f_data);
    if((sniff_d = (sniffer_d *)malloc(sizeof(sniffer_d))) == NULL){
        printf("Failed to allocate sniffer_d structure\n");
        clean_exit(pool, 1);
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

int start_writer(scan_p *args, int family){
    int fd;
    int protocol;
    writer_d *write_d;
    if((write_d = (writer_d *)malloc(sizeof(writer_d))) == NULL){
        printf("Failed to create writer_d structure\n");
        clean_exit(pool, 1);
    }
    add_allocation(pool->ptrs, (void *)write_d);
    switch(args->method){
        case SYN_METH:
            protocol = IPPROTO_TCP;
            break;
        default:
            protocol = 0;
            break;
    }
    fd = open_writer(family, protocol);
    if(fd < 0){
        printf("Failed to open socket\n");
        printf("- %s\n", strerror(errno));
        clean_exit(pool, 1);
    }
    pool->write_fd = fd;
    write_d->fd = fd;
    write_d->q = args->q;
    write_d->src = args->src;
    write_d->dst = args->dst;
    write_d->id = 0xcc73;
    write_d->sport = args->sport;
    write_d->method = args->method;
    pthread_create(&pool->write_thread, NULL, writer, (void *)write_d);
    return 0;
}

void *writer(void *data){
    writer_d *write_d = (writer_d *)data;
    packet_d *packet_data;
    short dport=0;
    char *packet=NULL;
    int r;
    packet_data = (packet_d *)malloc(sizeof(packet_d));
    if(packet_data == NULL){
        return NULL;
    }
    add_allocation(pool->ptrs, (void *)packet_data);
    packet_data->sport = write_d->sport;
    packet_data->dport = dport;
    packet_data->src = write_d->src;
    packet_data->dst = write_d->dst;
    packet_data->id = write_d->id;
    while(!isEmpty(write_d->q)){
        dport = pop(write_d->q);
        packet_data->dport = dport;
        if(((packet = buildPacket(packet, packet_data, write_d->method))) == NULL){
            return NULL;
        }
        r = sendData(write_d->fd, packet_data, packet, IP_SIZE+TCP_SIZE);
        free(packet);
        results->packets_sent += 1;
    }
    remove_allocation(pool->ptrs, get_ptr_index(pool->ptrs, packet_data));
    free(packet_data);
    return NULL;
}

void *sniffer(void *data){
    sniffer_d *args = (sniffer_d *)data;
    int responses=0, new=0, retries=0;
    int expected_responses;
    expected_responses = args->jobs;
    while((responses < expected_responses)){
        /* if we dont pick any packets up retry up to a max. of 5x */
        /* so that we dont just loop forever */
        if(retries == 5) break;
        new = sniff(args->fd, args->blen, (args->timeout*1000), SYN_METH);
        if(new == 0){
            retries += 1;
        }
        responses += new;
        results->packets_recvd = responses;
    }
    return NULL;
}

void display_results(results_d *r){
    int i=0;
    if(r->size){
        printf("\n");
        for(;i<r->size;i++){
            printf(" Port %hu is open\n", r->open_ports[i]);
        }
    }else printf("\nNo open ports found...\n");
    //printf("\n## Results ##\n");
    if(r->packets_sent) printf("\nSent %d packets. ", r->packets_sent);
    if(r->packets_recvd) printf("%d packets captured by filter", r->packets_recvd);
    printf("\n");
    return;
}

void signal_handler(int signal){
    //printf("\nCaught Interrupt...\n");
    display_results(results);
    clean_exit(pool, 130);
}
