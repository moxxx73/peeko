#include "../include/net.h"

extern results_d *results;
extern char verbose;

/* Wrapper for that son of a bitch sendto() 
int sendData(int s, scan_data *data, char *packet, int size){
    struct sockaddr_in dst;
    dst.sin_port = htons(data->dport);
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = data->dst_ip;
    return sendto(s, packet, size, 0, (struct sockaddr *)&dst, sizeof(struct sockaddr_in));
}*/

char *construct_packet(scan_data *data){
    struct tcphdr *tcph;
    struct tcpPseudo psd;
    char *packet_buf = NULL;
    packet_buf = (char *)malloc(IP_SIZE+TCP_SIZE);
    if(!packet_buf){
        err_msg("malloc()");
        return NULL;
    }
    ipv4Hdr(packet_buf, (short)(IP_SIZE+TCP_SIZE), 0x0073, 0x00, 64, IPPROTO_TCP, 0, data->src_ip, data->dst_ip);
    tcpHdr((packet_buf+IP_SIZE), data->sport, peek(data->dports), 0x115666, 0, 5, TH_SYN, 1024, 0, 0);
    tcph = (struct tcphdr *)(packet_buf+IP_SIZE);
    psd.src = data->src_ip;
    psd.dst = data->dst_ip;
    psd.protocol = IPPROTO_TCP;
    psd.length = htons(TCP_SIZE);
    memcpy(&psd.tcp, tcph, TCP_SIZE);
    tcph->th_sum = checksum((unsigned short *)&psd, sizeof(psd));
    return packet_buf;
}
