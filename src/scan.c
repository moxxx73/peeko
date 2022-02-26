#include "../include/scan.h"

#include "memory.h"

extern mem_obj *mem;
extern results_d *results;
extern char verbose;

int scan_mgr(scan_data *data, int method){
    if(method == HANDSHAKE_SCAN) connect_scan(data);
    else raw_scan(data, method);
    return 0;
}

int connect_scan(scan_data *data){
    struct sockaddr_in dst;
    stack *st_ptr;
    int sock;
    int i;
    short dport;

    st_ptr = data->dports;
    dst.sin_family = data->family;

    dst.sin_addr.s_addr = data->dst_ip;
    for(i=0;i<st_ptr->frame_size;i++){
        dport = pop(st_ptr);
        if(dport < 0){
            return 0;
        }
        dst.sin_port = htons(dport);
        sock = socket(data->family, SOCK_STREAM, 0);
        if(sock < 0){
            err_msg("socket()");
            return 0;
        }
        if(connect(sock, (struct sockaddr *)&dst, sizeof(struct sockaddr_in)) == 0){
            add_open_port(results, dport);
            if(verbose) printf("port %hu is open\n", dport);
        }
        shutdown(sock, SHUT_RDWR);
        close(sock);
        sock = -1;
    }
    return 1;
}

void read_write_cycle(int read_fd, int write_fd, scan_data *data, struct tpacket_req *treq){
    fd_set write_set={0}, read_set={0};
    struct timeval tv = {5, 0};
    struct sockaddr_in dst={0};
    struct tpacket2_hdr *tphdr;
    char *packet_ptr=NULL;
    char *buffer=NULL, *packet=NULL, *frame_ptr=NULL;
    char *recv_buffer=NULL;

    int expected = data->dports->frame_size;
    int count=0;
    int to_count = 0;
    int r = 0;

    unsigned long frame_dx = 0;
    unsigned long frame_dx_diff = 0;
    unsigned long bf_dx = 0;
    unsigned long fpb = 0;
    
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = data->dst_ip;

    FD_ZERO(&write_set);
    FD_ZERO(&read_set);

    recv_buffer = (char *)malloc(8192);
    if(!recv_buffer) return;
    add_allocation(mem, (void *)recv_buffer, 8192);

    if(stack_empty(data->dports)) return;
    while(!stack_empty(data->dports)){
        FD_SET(write_fd, &write_set);
        packet = construct_packet(data, 0);
        if(select((write_fd+1), NULL, &write_set, NULL, &tv) > 0){
            sendto(write_fd, packet, 40, 0, (struct sockaddr *)&dst, sizeof(struct sockaddr_in));
        }
        free(packet);
    }
    shutdown(write_fd, SHUT_RDWR);
    close(write_fd);
    write_fd = -1;
    mem->write_fd = -1;
    
    frame_ptr = mem->rx_ring;
    fpb = treq->tp_block_size/treq->tp_frame_size;

    while(count<expected){
        tphdr = (struct tpacket2_hdr *)frame_ptr;
        while(!(tphdr->tp_status&TP_STATUS_USER)){
            FD_SET(read_fd, &read_set);
            r = select((read_fd+1), &read_set, NULL, NULL, &tv);
            if(r < 0) return;
            else if(r == 0){
                if(to_count != 2) to_count += 1;
                else return;
            }
            recvfrom(read_fd, recv_buffer, 8192, 0, NULL, NULL);
        }
        frame_dx = (frame_dx+1)%treq->tp_frame_nr;
        bf_dx = frame_dx/fpb;

        buffer = (char *)(mem->rx_ring)+(bf_dx*treq->tp_block_size);
        frame_dx_diff = frame_dx%fpb;

        packet_ptr = (char *)frame_ptr+(tphdr->tp_mac);
        parse_packet(packet_ptr, tphdr->tp_len, data->open_flags);
        frame_ptr = (buffer)+(frame_dx_diff*treq->tp_frame_size);
        tphdr->tp_status = TP_STATUS_KERNEL;
        count += 1;
        results->packets_recvd = count;
    }
    return;
}

int raw_scan(scan_data *data, int method){
    int sock_write;
    filter_data filter_d;
    rsock_obj *read_obj;
    struct tpacket_req *tpk_ptr;

    char *template_packet;
    switch(method){
        case SYN_SCAN:
            data->open_flags = (TH_SYN|TH_ACK);
            data->scan_flags = TH_SYN;
            break;
    }
    filter_d.dst = data->dst_ip;
    filter_d.src = data->src_ip;
    filter_d.dport = data->sport;

    template_packet = construct_packet(data, 1);
    hex_dump((unsigned char *)template_packet, 40);
    free(template_packet);

    read_obj = read_socket(data->interface_name, 5, data->family);
    if(!read_obj){
        err_msg("read_socket()");
        clean_exit(mem, 1);
    }
    mem->rx_ring = read_obj->rx_ring;
    mem->rx_ring_size = read_obj->rx_ring_size;
    mem->recv_fd = read_obj->sock_fd;

    tpk_ptr = read_obj->tpack_r;
    add_allocation(mem, (void *)tpk_ptr, sizeof(struct tpacket_req));
    free(read_obj);

    sock_write = write_socket(AF_INET, IPPROTO_TCP);
    mem->write_fd = sock_write;

    if((read_obj->sock_fd < 0) || (sock_write < 0)){
        err_msg("socket()");
        clean_exit(mem, 1);
    }
    set_filter(read_obj->sock_fd, &filter_d);
    read_write_cycle(read_obj->sock_fd, sock_write, data, tpk_ptr);
    return 0;
}

void signal_handler(int signal){
    printf("\n");
    clean_exit(mem, 130);
}
