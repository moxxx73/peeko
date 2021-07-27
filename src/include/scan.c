#include "scan.h"

/* not just for probing a single port but also for testing purposes */
int single_port(char *ifn, unsigned int src, unsigned int dst, short dport, short sport, int v){
    struct sockaddr_in dst_in;
    char *packet;
    int sw, sr, r, y=1;
    dst_in.sin_family = AF_INET;
    dst_in.sin_addr.s_addr = dst;
    dst_in.sin_port = htons(dport);
    sr = openDev();
    if(sr < 0) return 1;
    r = setAll(sr, ifn);
    if(r > 0 && (v == 1)) printf("[+] Opened /dev/bpf (Buffer: %d)\n", r);
    packet = (char *)malloc(IP_SIZE+TCP_SIZE);
    if(packet == NULL){
        return -1;
    }
    sw = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if(sw < 0){
        printf("[!] Failed to open socket\n");
        return 1;
    }
    if(setsockopt(sw, IPPROTO_IP, IP_HDRINCL, &y, sizeof(y)) < 0){
        printf("[!] Call to setsockopt() failed\n");
        return 1;
    }
    buildSYN(packet, src, dst, sport, dport, 0x0073);
    if(sendto(sw, packet, (IP_SIZE+TCP_SIZE), 0, (struct sockaddr *)&dst_in, sizeof(struct sockaddr_in)) < 0){
        printf("[!] Error in sendto()\n");
        return 1;
    }
    printf("[+] Sent packet\n");  
    free(packet);
    close(sw);
    close(sr);
    return 0;
}
