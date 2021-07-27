#include "cafebabe.h"

int resolve_name(char *name, char *b){
    struct hostent *r;
    r = gethostbyname(name);
    if(r != NULL){
        if(inet_ntop(AF_INET, ((struct sockaddr_in *)r->h_addr_list[0]), b, INET_ADDRSTRLEN) != NULL){
            return 0;
        }
    }
    return -1;
}

int getifaddr(char *ifn, char *b){
    struct ifreq ifr;
    int s;
    s = socket(AF_INET, SOCK_STREAM, 0);
    if(s < 0) return -1;
    ifr.ifr_addr.sa_family = AF_INET;
    memcpy(ifr.ifr_name, ifn, IFNAMSIZ);
    if(ioctl(s, SIOCGIFADDR, &ifr) < 0){
        return -1;
    }
    close(s);
    if(inet_ntop(AF_INET, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, b, INET_ADDRSTRLEN) == NULL){
        return -1;
    }
    return 0;
}

int cafebabe_main(cafebabe *args, char *name, int t){
    int r, jpt, rm;
    unsigned int u_src, u_dst;
    char src[INET_ADDRSTRLEN];
    if(args->porta <= 0){
        return 1;
    }
    r = resolve_name(name, args->addr);
    if(r != 0){
        return 1;
    }
    if(args->verbose == 1) printf("[+] Target: %s (%s)\n", name, args->addr);
    if(getifaddr(args->ifn, src) < 0){
        printf("[!] Failed to fetch interface address\n");
        return 1;
    }
    if(args->verbose==1) printf("[+] Interface: %s (%s)\n", args->ifn, src);
    if(args->portb != 0){
        r = args->portb-args->porta;
        if(r < 0) return 1;
        jpt = r/t;
        rm = r%t;
        //init_threads();
    }
    inet_pton(AF_INET, args->addr, &u_dst);
    inet_pton(AF_INET, src, &u_src);
    single_port(args->ifn, u_dst, u_src, (short)args->porta, (short)args->portc, args->verbose);
    return 0;
}
