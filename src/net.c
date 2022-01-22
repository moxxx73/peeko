#include "../include/net.h"

extern results_d *results;
extern char verbose;

char *construct_packet(scan_data *data, char peek_flag){
    struct tcphdr *tcph;
    struct tcpPseudo psd;
    short (*fetch_port)(stack *) = NULL;
    char *packet_buf = NULL;
    packet_buf = (char *)malloc(IP_SIZE+TCP_SIZE);
    if(!packet_buf){
        err_msg("malloc()");
        return NULL;
    }
    if(peek_flag) fetch_port = &peek;
    else fetch_port = &pop;
    ipv4Hdr(packet_buf, (short)(IP_SIZE+TCP_SIZE), 0x0073, 0x00, 64, IPPROTO_TCP, 0, data->src_ip, data->dst_ip);
    tcpHdr((packet_buf+IP_SIZE), data->sport, fetch_port(data->dports), 0x115666, 0, 5, TH_SYN, 1024, 0, 0);
    tcph = (struct tcphdr *)(packet_buf+IP_SIZE);
    psd.src = data->src_ip;
    psd.dst = data->dst_ip;
    psd.protocol = IPPROTO_TCP;
    psd.length = htons(TCP_SIZE);
    psd.null = 0x00;
    memcpy(&psd.tcp, tcph, TCP_SIZE);
    tcph->th_sum = checksum((unsigned short *)&psd, sizeof(psd));
    return packet_buf;
}

int parse_packet(char *packet, int packet_length, short positive_flag){
    struct tcphdr *tcp;
    int minsiz = (ETH_SIZE+IP_SIZE+TCP_SIZE);
    if(packet_length < minsiz) return -1;
    tcp = (struct tcphdr *)(packet+(ETH_SIZE+IP_SIZE));
    //printf("%hu = %hu\n", positive_flag, ntohs(tcp->th_flags));
    if(positive_flag == tcp->th_flags) add_open_port(results, ntohs(tcp->th_sport));
    return 0;
}
