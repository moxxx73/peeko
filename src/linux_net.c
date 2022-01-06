#include "../include/linux_net.h"

int read_socket(char *ifn, int timeout, int family){
    int r;
    struct ifreq ifr;
    struct timeval tm;
    memcpy(&ifr, ifn, IFNAMSIZ);
    r = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(r < 0) return -1;
    if(setsockopt(r, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0){
        close(r);
        return -1;
    }
    tm.tv_usec = 0;
    tm.tv_sec = timeout;
    if(setsockopt(r, SOL_SOCKET, SO_RCVTIMEO, &tm, sizeof(tm)) < 0){
        close(r);
        return -1;
    }
    return r;
}

int write_socket(int family, int protocol){
    int fd, y=1;
    fd = socket(family, SOCK_RAW, protocol);
    if(fd < 0) return -1;
    if(setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &y, sizeof(y)) < 0){
        close(fd);
        return -1;
    }
    return fd;
}