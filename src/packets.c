#include "../include/packets.h"

/* TCP checksum algorithm */
unsigned short checksum(unsigned short *p, int l){
    unsigned long sum=0;
    while(l>1){
        sum += (unsigned short)*p++;
        l-=2;
    }
    if(l > 0) sum += (unsigned char)*p++;
    while(sum>>16){
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return (unsigned short)(~sum);
}

/* assigns IPv4 header fields */
void ipv4Hdr(char *b, unsigned short l, unsigned short id, unsigned short off, unsigned char ttl, unsigned char p, unsigned short sum, unsigned int src, unsigned int dst){
    struct ip *iphdr = (struct ip *)(b);
    iphdr->ip_hl = 5;
    iphdr->ip_v = 4;
    iphdr->ip_tos = 0;
    iphdr->ip_len = l;
    iphdr->ip_id = htons(id);
    iphdr->ip_off = off;
    iphdr->ip_ttl = ttl;
    iphdr->ip_p = p;
    iphdr->ip_sum = sum;
    iphdr->ip_src.s_addr = src;
    iphdr->ip_dst.s_addr = dst;
    return;
}

/* assigns TCP header fields */
void tcpHdr(char *b, unsigned short sport, unsigned short dport, unsigned int seq, unsigned int ack, unsigned char off, unsigned char flags, unsigned short win, unsigned short sum, unsigned short urp){
    struct tcphdr *tcph = (struct tcphdr *)(b);
    tcph->th_sport = htons(sport);
    tcph->th_dport = htons(dport);
    tcph->th_seq = htonl(seq);
    tcph->th_ack = htonl(ack);
    tcph->th_off = off;
    tcph->th_win = htons(win);
    tcph->th_flags = flags;
    tcph->th_sum = htons(sum);
    tcph->th_urp = htons(urp);
    return;
}