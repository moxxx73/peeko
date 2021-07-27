#include "framez.h"

/*TCP checksum algorithm*/
unsigned short checksum(unsigned short *p, int l){
    unsigned long sum=0;
    while(l>1){
        sum += htons(*p++);
        l-=2;
    }
    sum += (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

//buildIPv4(pkt, packetLength, 115, 0, 64, IPPROTO_TCP, 0, a->src, a->dst);
void ipv4Hdr(char *b, unsigned short l, unsigned short id, unsigned short off, unsigned char ttl, unsigned char p, unsigned short sum, unsigned src, unsigned dst){
    struct ip *iphdr = (struct ip *)b;
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

//buildTCP(pkt, a->srcPort, a->dstPort, 0x115666, 0, 5, TH_SYN, (short)a->maxLength, 0, 0);
void tcpHdr(char *b, unsigned short sport, unsigned short dport, unsigned int seq, unsigned int ack, unsigned char off, unsigned char flags, unsigned short win, unsigned short sum, unsigned short urp){
    struct tcphdr *tcph = (struct tcphdr *)b;
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

void buildSYN(char *buffer, unsigned int src, unsigned int dst, short sport, short dport, short id){
    ipv4Hdr(buffer, (IP_SIZE+TCP_SIZE), id, 0, 64, IPPROTO_TCP, 0, src, dst);
    tcpHdr((buffer+IP_SIZE), sport, dport, 0x115666, 0, 0, TH_SYN, 1024, 0, 0);
    return;
}
