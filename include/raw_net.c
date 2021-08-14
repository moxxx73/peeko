#include "networkshit.h"

/* now i could just use /dev/bpf but i have to also create the ethernet */
/* header which i just cannot be arsed doing atm */
int write_socket(int family, int protocol){
    int s, y=1;
    s = socket(family, SOCK_RAW, protocol);
    if(s < 0) return -1;
    /* yes ik, i give the option for the protocol but this call to setsockopt */
    /* is pretty set in stone, thats temporary ok? jeeez */
    if(setsockopt(s, IPPROTO_IP, IP_HDRINCL, &y, sizeof(y)) < 0) return -1;
    return s;
}

/* Wrapper for that son of a bitch sendto() */
int sendData(int s, packet_d *data, char *packet, int size){
    struct sockaddr_in dst;
    int r;
    dst.sin_port = htons(data->dport);
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = data->dst;
    r = sendto(s, packet, size, 0, (struct sockaddr *)&dst, sizeof(struct sockaddr_in));
    return r;
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

/* deprecated function */
int checkFrames(char *data, packet_d *info){
    struct ip *iph;
    struct ether_header *eth;
    //struct tcphdr *tcph;
    eth = (struct ether_header *)(data);
    if(ntohs(eth->ether_type) != ETHERTYPE_IP) return -1;
    iph = (struct ip *)(data+ETH_SIZE);
    if(iph->ip_src.s_addr == info->dst && iph->ip_dst.s_addr == info->src){
        if(iph->ip_p != IPPROTO_TCP) return -1;
        return 0;
    }
    return -1;
}