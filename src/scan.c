#include "../include/scan.h"

#include "memory.h"

extern pool_d *pool;
extern results_d *results;

char retry=0;


int scan_mgr(scan_p *scan_data){
    switch(scan_data->method){
        case HANDSHAKE_SCAN:
            connect_scan(scan_data);
            break;
        default:
            //raw_scan(scan_data);
            break;
    }
    return 0;
}

/* as of now there is no mutex locking as there are only two */
/* threads and they both have their own data structures to */
/* interact with */

int connect_scan(scan_p *scan_data){
    struct sockaddr_in dst;
    stack *st_ptr;
    int sock;
    int addr_sz;
    int i;
    short dport;

    st_ptr = scan_data->stk;
    dst.sin_family = scan_data->family;

    if(dst.sin_family == AF_INET) addr_sz = INET_ADDRSTRLEN;
    else addr_sz = INET6_ADDRSTRLEN;
    dst.sin_addr.s_addr = scan_data->dst;
    
    for(i=0;i<st_ptr->frame_size;i++){
        dport = pop(st_ptr);
        if(dport < 0){
            return 0;
        }
        dst.sin_port = htons(dport);
        sock = socket(scan_data->family, SOCK_STREAM, 0);
        if(sock < 0){
            err_msg("socket()");
            return 0;
        }
        if(connect(sock, (struct sockaddr *)&dst, sizeof(struct sockaddr_in)) == 0){
            add_open_port(results, dport);
        }
        shutdown(sock, SHUT_RDWR);
        close(sock);
        sock = -1;        
    }
    return 1;
}

int start_sniffer(scan_p *recv_p){
    filter_data *f_data;
    sniffer_d *sniff_d;
    int fd;
    int blen;
    int *r, index;

    f_data = (filter_data *)malloc(sizeof(filter_data));
    if(f_data == NULL){
        printf("Failed to allocate bpf_filter structure\n");
        clean_exit(pool, 1);
    }
    f_data->src = recv_p->src;
    f_data->dst = recv_p->dst;
    f_data->dport = recv_p->sport;
    add_allocation(pool, (void *)f_data, FILTER_SIZ, "filter\0");
    if((r = open_recvr(recv_p->ifn, recv_p->timeout, recv_p->family)) == NULL){
        printf("Failed to open descriptor: %s\n", strerror(errno));
        clean_exit(pool, 1);
    }
    fd = r[0];
    pool->recv_fd = fd;
    blen = r[1];
    free(r);
    if(set_filter(fd, f_data) < 0){
        printf("Failed to set filter: %s\n", strerror(errno));
        clean_exit(pool, 1);
    }
    index = get_ptr_index(pool->ptrs, (void *)f_data);
    remove_allocation(pool, index);
    free(f_data);
    if((sniff_d = (sniffer_d *)malloc(sizeof(sniffer_d))) == NULL){
        printf("Failed to allocate sniffer_d structure\n");
        clean_exit(pool, 1);
    }
    sniff_d->fd = fd;
    sniff_d->blen = blen;
    sniff_d->jobs = recv_p->stk->frame_size;
    sniff_d->method = recv_p->method;
    sniff_d->timeout = recv_p->timeout;
    add_allocation(pool, (void *)sniff_d, RECV_A_SIZ, "Rthread\0");
    pthread_create(&pool->recv_thread, NULL, sniffer, (void *)sniff_d);
    return 0;
}

int start_writer(scan_p *args){
    int fd;
    int protocol;
    writer_d *write_d;
    if((write_d = (writer_d *)malloc(sizeof(writer_d))) == NULL){
        printf("Failed to create writer_d structure\n");
        clean_exit(pool, 1);
    }
    add_allocation(pool, (void *)write_d, WRITE_A_SIZ, "Wthread\0");
    switch(args->method){
        case SYN_METH:
            protocol = IPPROTO_TCP;
            break;
        default:
            protocol = 0;
            break;
    }
    fd = open_writer(args->family, protocol);
    if(fd < 0){
        printf("Failed to open socket\n");
        printf("- %s\n", strerror(errno));
        clean_exit(pool, 1);
    }
    pool->write_fd = fd;
    write_d->fd = fd;
    write_d->st = args->stk;
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
    packet_data = (packet_d *)malloc(sizeof(packet_d));
    if(packet_data == NULL){
        return NULL;
    }
    add_allocation(pool, (void *)packet_data, PACKET_D_SIZ, "packet-data\0");
    packet_data->sport = write_d->sport;
    packet_data->dport = dport;
    packet_data->src = write_d->src;
    packet_data->dst = write_d->dst;
    packet_data->id = write_d->id;
    while(!stack_empty(write_d->st)){
        dport = pop(write_d->st);
        packet_data->dport = dport;
        if(((packet = buildPacket(packet, packet_data, write_d->method))) == NULL){
            return NULL;
        }
        sendData(write_d->fd, packet_data, packet, IP_SIZE+TCP_SIZE);
        free(packet);
        results->packets_sent += 1;
    }
    remove_allocation(pool, get_ptr_index(pool->ptrs, packet_data));
    free(packet_data);
    return NULL;
}

void *sniffer(void *data){
    sniffer_d *args = (sniffer_d *)data;
    int responses=0, new=0, retries=0;
    int expected_responses;
    expected_responses = args->jobs;
    while((responses < expected_responses)){
        if(retries == 2) break;
        new = sniff(args->fd, args->blen, (args->timeout*1000), SYN_METH);
        if(!new){
            new = sniff(args->fd, args->blen, (args->timeout*1000), SYN_METH);
        }
        responses += new;
        results->packets_recvd = responses;
    }
    return NULL;
}

void signal_handler(int signal){
    clean_exit(pool, 130);
}
