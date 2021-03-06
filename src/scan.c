#include "../include/scan.h"

#include "memory.h"

extern mem_obj *mem;
extern results_d *results;
extern char verbose;

/* executes either raw_scan or connect scan */
/* based on the method provided             */
int scan_mgr(scan_data *data, int method){
    struct ifreq ifr;
    int tun_flag=1;
    int dummy_sock=0;
    int addr_index=0;
    /* connect_scan() is the default, unprivileged scan */
    /* so not much setup is needed                      */
    if(method == HANDSHAKE_SCAN) connect_scan(data);
    /* none of what we do for the raw scan is necessary for       */
    /* the connect as we are using the connect() syscall, as such */
    /* the kernel will handle this operations instead             */
    else{
        /* to fetch interface data we need to provide a socket */
        /* so this throw away on will do                       */
        memcpy(ifr.ifr_name, data->interface_name, IFNAMSIZ);
        dummy_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if(dummy_sock < 0){
            err_msg("socket()");
            clean_exit(mem, 1);
        }
        /* fetches the MAC address of the interface is specified in */
        /* struct ifreq ifr                                         */
        if(ioctl(dummy_sock, SIOCGIFHWADDR, &ifr) < 0){
            err_msg("ioctl()");
            shutdown(dummy_sock, SHUT_RDWR);
            close(dummy_sock);
            clean_exit(mem, 1);
        }
        /* determine whether the tunnel interface has a MAC                            */
        /* address, this is for determining which layer the tunnel supports            */
        /* which will be important when applying a filter and parsing received packets */
        for(;addr_index<6;addr_index++){
            if(ifr.ifr_addr.sa_data[addr_index] != 0x00){
                tun_flag = 0;
                break;
            }
        }
        shutdown(dummy_sock, SHUT_RDWR);
        close(dummy_sock);
        raw_scan(data, method, tun_flag);

    }
    return 0;
}

/* very simple scan uitilising the connect() syscall */
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

void read_write_cycle(int read_fd, int write_fd, scan_data *data, struct tpacket_req *treq, int tun){
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
                if(to_count == 5) return;
                else to_count += 1;
            }
            r = recvfrom(read_fd, recv_buffer, 8192, 0, NULL, NULL);
            if(r > 0) parse_packet(recv_buffer, 8192, data->open_flags, tun);
        }
        frame_dx = (frame_dx+1)%treq->tp_frame_nr;
        bf_dx = frame_dx/fpb;

        buffer = (char *)(mem->rx_ring)+(bf_dx*treq->tp_block_size);
        frame_dx_diff = frame_dx%fpb;

        packet_ptr = (char *)frame_ptr+(tphdr->tp_mac);
        parse_packet(packet_ptr, tphdr->tp_len, data->open_flags, tun);
        frame_ptr = (buffer)+(frame_dx_diff*treq->tp_frame_size);
        tphdr->tp_status = TP_STATUS_KERNEL;
        count += 1;
        results->packets_recvd = count;
    }
    return;
}

int raw_scan(scan_data *data, int method, int tun){
    int sock_write=0, r=0;
    filter_data filter_d={0};
    rsock_obj *read_obj=NULL;
    struct tpacket_req *tpk_ptr=NULL;
    char *template_packet=NULL;

    /* determining positive case TCP flags               */
    /* based on the selected method, this allows         */
    /* for alternate methods to be easily added          */
    /* as after this point we aren't actually concerned  */
    /* with what method/flags are set only if they match */
    /* with the flags we're looking for                  */
    switch(method){
        case SYN_SCAN:
            data->open_flags = (TH_SYN|TH_ACK);
            data->scan_flags = TH_SYN;
            break;
    }

    /* narrows down the reception               */
    /* to only the dst_ip & src_ip:src_port     */
    /* filter operations defined in:            */
    /*    + peeko/include/net_filter.h       */
    /*    + peeko/src/net_filter.c           */
    filter_d.dst = data->dst_ip;
    filter_d.src = data->src_ip;
    filter_d.dport = data->sport;

    /* doesn't serve any real purpose other than looking nice */
    template_packet = construct_packet(data, 1);
    hex_dump((unsigned char *)template_packet, 40);
    free(template_packet);

    /* handling of the receiving socket & getting packets */
    /* is alot different then how its usually done due to */
    /* increasing performance. as such alot of it will be */
    /* documented in peeko/src/linux_net.c and in an   */
    /* upcoming paper.                                    */
    read_obj = read_socket(data->interface_name, 5, data->family);
    if(!read_obj){
        err_msg("read_socket()");
        clean_exit(mem, 1);
    }
    /* also related to the handling packets, again this is mentioned */
    /* later on                                                      */
    mem->rx_ring = read_obj->rx_ring;
    mem->rx_ring_size = read_obj->rx_ring_size;
    mem->recv_fd = read_obj->sock_fd;

    tpk_ptr = read_obj->tpack_r;
    add_allocation(mem, (void *)tpk_ptr, sizeof(struct tpacket_req));
    free(read_obj);

    /* the transmitting socket is very basic in comparison with the      */
    /* receving socket and should be pretty familiar to anyone whos used */
    /* sockets in the past                                               */
    sock_write = write_socket(AF_INET, IPPROTO_TCP);
    mem->write_fd = sock_write;

    /* as the scan is dependant on both sockets, if either one has failed */
    /* we have to abort                                                   */
    if((read_obj->sock_fd < 0) || (sock_write < 0)){
        err_msg("socket()");
        clean_exit(mem, 1);
    }

    /* set the socket filter */
    r = set_filter(read_obj->sock_fd, &filter_d, tun);
    if(r < 0) clean_exit(mem, 1);

    read_write_cycle(read_obj->sock_fd, sock_write, data, tpk_ptr, tun);
    return 0;
}
