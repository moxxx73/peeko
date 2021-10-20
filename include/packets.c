#include "packets.h"

short get_sport(char *packet){
    struct tcphdr *tcp;
    short sport=0;
    tcp = (struct tcphdr *)(packet+ETH_SIZE+IP_SIZE);
    sport = tcp->th_sport;
    return ntohs(sport);
}

/* Wrapper for that son of a bitch sendto() */
int sendData(int s, packet_d *data, char *packet, int size){
    struct sockaddr_in dst;
    dst.sin_port = htons(data->dport);
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = data->dst;
    return sendto(s, packet, size, 0, (struct sockaddr *)&dst, sizeof(struct sockaddr_in));
}

/* TCP checksum algorithm */
/* the bane of my fucking life */
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

/* does not need an explanation */
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

/* same as the above */
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

/* constructs a tcp packet with a syn flag */
/* allocates memory (size: SYNSIZ) and fills */
/* buffer with the data provided in ptr */
void buildSYN(char *buffer, packet_d *ptr){
    struct tcphdr *tcp;
    struct tcpPseudo pseudo;
    ipv4Hdr(buffer, SYNSIZ, ptr->id, 0, 64, IPPROTO_TCP, 0, ptr->src, ptr->dst);
    tcpHdr((buffer+IP_SIZE), ptr->sport, ptr->dport, 0x115666, 0, 5, TH_SYN, 1024, 0, 0);
    tcp = (struct tcphdr *)(buffer+IP_SIZE);
    pseudo.src = ptr->src;
    pseudo.dst = ptr->dst;
    pseudo.length = htons(TCP_SIZE);
    pseudo.null = 0x00;
    pseudo.protocol = IPPROTO_TCP;
    memcpy(&pseudo.tcp, tcp, TCP_SIZE);
    tcp->th_sum = checksum((unsigned short *)&pseudo, sizeof(pseudo));
    return;
}

/* deccides what packet to create based on the provided */
/* scan method */
char *buildPacket(char *b, packet_d *ptr, int method){
    switch(method){
        case SYN_METH:
            b = (char *)malloc(SYNSIZ);
            memset(b, 0, SYNSIZ);
            if(b == NULL) return NULL;
            buildSYN(b, ptr);
            break;
    }
    return b;
}

int _state(char *packet, int method){
    /* filter only allows for ipv4+tcp packets */
    struct tcphdr *tcp = (struct tcphdr *)(packet+ETHSIZ+IPSIZ);
    switch(method){
        case SYN_METH:
            if(tcp->th_flags == (TH_SYN|TH_ACK)) return 1;
            break;
        default:
            return 0;
    }
    return 0;
}