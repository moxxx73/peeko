#include "../include/net.h"

extern results_d *results;
extern char verbose;

/* allocates a packet and sets the IPv4 and TCP fields */
char *construct_packet(scan_data *data, char peek_flag){
    struct tcphdr *tcph=NULL;
    struct tcpPseudo psd={0};
    short (*fetch_port)(stack *) = NULL;
    char *packet_buf = NULL;

    packet_buf = (char *)malloc(IP_SIZE+TCP_SIZE);
    if(!packet_buf){
        err_msg("malloc()");
        return NULL;
    }

    /* used for the hex dump in scan.c:raw_scan()          */
    /* as to not alter the stack in the name of aesthetics */
    if(peek_flag) fetch_port = &peek;
    else fetch_port = &pop;

    /* set IPv4 and TCP header fields */
    ipv4Hdr(packet_buf, (short)(IP_SIZE+TCP_SIZE), 0x0073, 0x00, 64, IPPROTO_TCP, 0, data->src_ip, data->dst_ip);
    tcpHdr((packet_buf+IP_SIZE), data->sport, fetch_port(data->dports), 0x115666, 0, 5, TH_SYN, 1024, 0, 0);
    tcph = (struct tcphdr *)(packet_buf+IP_SIZE);

    /* set pseudo header fields for checksum */
    psd.src = data->src_ip;
    psd.dst = data->dst_ip;
    psd.protocol = IPPROTO_TCP;
    psd.length = htons(TCP_SIZE);
    psd.null = 0x00;
    memcpy(&psd.tcp, tcph, TCP_SIZE);
    
    tcph->th_sum = checksum((unsigned short *)&psd, sizeof(psd));
    return packet_buf;
}

/* parse responses and determine whether provided flags match with positive_flag */
int parse_packet(char *packet, int packet_length, short positive_flag, int tun){
    struct tcphdr *tcp;
    int minsiz = (IP_SIZE+TCP_SIZE);
    int offset = IP_SIZE;
    /* if the interface we're operating on is a layer 3 tunnel        */
    /* then theres no ethernet header to parse and instead begin with */
    /* the IPv4 header */
    if(!tun){
        minsiz += ETH_SIZE;
        offset += ETH_SIZE;
    }
    if(packet_length < minsiz) return -1;
    tcp = (struct tcphdr *)(packet+(offset));
    if(positive_flag == tcp->th_flags){
        add_open_port(results, ntohs(tcp->th_sport));
    }
    return 0;
}
