#include "cafebabe.h"

extern char verbose;
extern char debug;
extern char underline[];
extern char reset[];

pool_d *pool = NULL;

queue *create_queue(parse_r *list){
    int i;
    queue *ret = init_queue(list->llen);
    if(ret != NULL){
        for(i=0;i<list->llen;i++){
            push(ret, list->list[i]);
        }
        return ret;
    }
    return NULL;
}

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

int cafebabe_main(cafebabe *args, char *name, parse_r *l, int t){
    int r=0;
    char src_str[INET_ADDRSTRLEN];
    scan_p *scan_args = NULL;
    queue *q = NULL;
    r = resolve_name(name, args->addr);
    if(r != 0){
        return 1;
    }
    //printf("Target: %s (%s)\n", name, args->addr);
    if(getifaddr(args->ifn, src_str) < 0){
        printf("[!] Failed to fetch interface address\n");
        return 1;
    }
    printf("Operating on interface: %s (%s)\n", args->ifn, src_str);

    if((pool = create_pool(pool)) == NULL){
        printf("Failed to allocate pool memory\n");
        free(l);
        free(args);
        return 1;
    }

    scan_args = (scan_p *)malloc(sizeof(scan_p));
    if(scan_args == NULL){
        printf("[!] Failed to initialise scan_p structure\n");
        return 1;
    }
    if(debug) printf("\t\t%s[DEBUG]%s Allocated scan_p @ %p\n", underline, reset, (void *)scan_args);
    add_allocation(pool->ptrs, (void *)scan_args);
    q = create_queue(l);
    if((q != NULL) && (debug)){
        printf("\t\t%s[DEBUG]%s Initialised queue @ %p\n", underline, reset, (void *)q);
        printf("\t\t        Data allocated @ %p\n", (void *)q->data);
        printf("\t\t        Length: %d\n", q->size);
    }
    add_allocation(pool->ptrs, (void *)q);
    inet_pton(AF_INET, args->addr, &scan_args->dst);
    inet_pton(AF_INET, src_str, &scan_args->src);
    scan_args->sport = args->sport;
    scan_args->ifn = args->ifn;
    scan_args->q = q;
    scan_args->method = args->method;
    signal(SIGINT, signal_handler);
    if(scan_args->method > 0){
        //if(debug) printf("\t\t%s[DEBUG]%s Calling start_sniffer (%p)\n", underline, reset, (void *)&start_sniffer);
        start_sniffer(scan_args);
        clean_exit(pool);
    }
    /*else{
        tcp_connect();
    }*/
    return 0;
}
