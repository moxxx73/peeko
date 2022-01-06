#include "../include/scan.h"

#include "memory.h"

extern pool_d *pool;
extern results_d *results;

int scan_mgr(scan_data *data, int method){
    if(method == HANDSHAKE_SCAN) connect_scan(data);
    else raw_scan(data, method);
    return 0;
}

int connect_scan(scan_data *data){
    struct sockaddr_in dst;
    stack *st_ptr;
    int sock;
    int i;
    short dport;

    st_ptr = data->dports;
    dst.sin_family = data->family;

    dst.sin_addr.s_addr = data->dst_ip;
    
    for(i=0;i<st_ptr->frame_size;i++){
        dport = pop(st_ptr);
        if(dport < 0){
            return 0;
        }
        dst.sin_port = htons(dport);
        sock = socket(data->family, SOCK_STREAM, 0);
        if(sock < 0){
            err_msg("socket()");
            return 0;
        }
        if(connect(sock, (struct sockaddr *)&dst, sizeof(struct sockaddr_in)) == 0){
            add_open_port(results, dport);
        }
        shutdown(sock, SHUT_RDWR);
        close(sock);
        sock = -1;        
    }
    return 1;
}

int raw_scan(scan_data *data, int method){
    char *template_packet; /* not really important but i thought itd be fun ^_^ */
    /* also its not really a template per say, but whatevs */
    switch(method){
        /* its the only supported raw scan method for now */
        /* but i do wanna implement more, with the way that */
        /* this has been setup shouldnt be hard at all... */
        case SYN_SCAN:
            data->open_flags = (TH_SYN|TH_ACK);
            data->scan_flags = TH_SYN;
            break;
    }
    template_packet = construct_packet(data);
    hex_dump((unsigned char *)template_packet, 40);
    return 0;
}

void signal_handler(int signal){
    clean_exit(pool, 130);
}
