#include "../include/linux_net.h"

rsock_obj *read_socket(char *ifn, int timeout, int family){
    rsock_obj *r=NULL;
    int fd=-1, sf=0;
    struct ifreq ifr = {0};
    struct timeval tm = {0};
    int ver = TPACKET_V2;
    unsigned long fpb = 0;

    r = (rsock_obj *)malloc(sizeof(rsock_obj));
    if(!r) return NULL;
    r->tpack_r = (struct tpacket_req *)malloc(sizeof(struct tpacket_req));
    if(!r->tpack_r) return NULL;

    memcpy(&ifr, ifn, IFNAMSIZ);
    fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(fd < 0) return NULL;
    if(setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0) goto rs_err_exit;

    tm.tv_usec = 0;
    tm.tv_sec = timeout;
    if(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tm, sizeof(tm)) < 0) goto rs_err_exit;
    
    sf = fcntl(fd, F_GETFL, 0);
    if(sf < 0) goto rs_err_exit;
    sf = sf|O_NONBLOCK;
    if(fcntl(fd, F_SETFL, sf) < 0) goto rs_err_exit;

    if(setsockopt(fd, SOL_PACKET, PACKET_VERSION, &ver, sizeof(ver)) < 0) goto rs_err_exit;
    r->tpack_r->tp_frame_size = TPACKET_ALIGN(TPACKET2_HDRLEN+14+20+20+16); // 128
    r->tpack_r->tp_block_size = sysconf(_SC_PAGESIZE);
    while(r->tpack_r->tp_block_size < r->tpack_r->tp_frame_size){
        r->tpack_r->tp_block_size <<= 1;
    }
    fpb = r->tpack_r->tp_block_size/r->tpack_r->tp_frame_size;
    r->tpack_r->tp_block_nr = 520;
    r->tpack_r->tp_frame_nr = r->tpack_r->tp_block_nr*fpb;

    r->rx_ring_size = r->tpack_r->tp_block_size*r->tpack_r->tp_block_nr;

    if(setsockopt(fd, SOL_PACKET, PACKET_RX_RING, r->tpack_r, sizeof(struct tpacket_req)) < 0) goto rs_err_exit;

    r->rx_ring = mmap(0, r->rx_ring_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    //printf("Socket Ring Buffer @ %p\n", ring);
    if(!r->rx_ring_size) goto rs_err_exit;
    r->sock_fd = fd;
    return r;

rs_err_exit:
    if(r){
        if(r->tpack_r) free(r->tpack_r);
        if(r->rx_ring) munmap(r->rx_ring, r->rx_ring_size);
        if(r->sock_fd > 0){
            shutdown(r->sock_fd, SHUT_RDWR);
            close(r->sock_fd);
        }
        free(r);
    }
    return NULL;
}

int write_socket(int family, int protocol){
    int fd, y=1;
    int sf;
    fd = socket(family, SOCK_RAW, protocol);
    if(fd < 0) return -1;
    if(setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &y, sizeof(y)) < 0) goto ws_err_exit;
    
    sf = fcntl(fd, F_GETFL, 0);
    if(sf < 0) goto ws_err_exit;

    sf |= O_NONBLOCK;
    if(fcntl(fd, F_SETFL, sf) < 0) goto ws_err_exit;
    return fd;
ws_err_exit:
    shutdown(fd, SHUT_RDWR);
    close(fd);
    return -1;
}