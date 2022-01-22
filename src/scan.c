#include "../include/scan.h"

#include "memory.h"

extern pool_d *pool;
extern results_d *results;
extern char verbose;

pthread_mutex_t stack_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t stdout_lock = PTHREAD_MUTEX_INITIALIZER;

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
            if(verbose) printf("port %hu is open\n", dport);
        }
        shutdown(sock, SHUT_RDWR);
        close(sock);
        sock = -1;
    }
    return 1;
}

void *write_packets(void *arg){
    scan_data *data = (scan_data *)arg;
    struct sockaddr_in dst;
    int sock;
    char *packet;

    if(stack_empty(data->dports)) return NULL;

    sock = write_socket(AF_INET, IPPROTO_TCP);
    if(sock < 0){
        return NULL;
    }

    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = data->dst_ip;

    while(!stack_empty(data->dports)){

        pthread_mutex_lock(&stack_lock);
        packet = construct_packet(data, 0);
        pthread_mutex_unlock(&stack_lock);

        sendto(sock, packet, 40, 0, (struct sockaddr *)&dst, sizeof(dst));
    }

    shutdown(sock, SHUT_RDWR);
    close(sock);
    return NULL;
}

int spawn_threads(scan_data *data){
    int x=0;
    int thread_count = data->thread_c;
    pool->write_threads = (pthread_t *)malloc((sizeof(pthread_t)*thread_count));
    if(!pool->write_threads){
        err_msg("malloc()");
        clean_exit(pool, 1);
    }
    pool->wthread_c = thread_count;
    for(;x<pool->wthread_c;x++){
        pthread_create(&pool->write_threads[x], NULL, write_packets, (void *)data);
    }
    return 0;
}

int raw_scan(scan_data *data, int method){
    int r, x=0;
    int packet_count=0, expected_responses;
    int sock;
    filter_data filter_d;
    char *recv_buffer;
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
    expected_responses = data->dports->frame_size;
    filter_d.dst = data->dst_ip;
    filter_d.src = data->src_ip;
    filter_d.dport = data->sport;
    /* nothing more than aesthetic */
    template_packet = construct_packet(data, 1);
    hex_dump((unsigned char *)template_packet, 40);
    free(template_packet);

    recv_buffer = (char *)malloc(4096);
    if(!recv_buffer){
        err_msg("malloc()");
        clean_exit(pool, 1);
    }

    sock = read_socket(data->interface_name, 5, data->family);
    if(sock < 0){
        err_msg("socket()");
        clean_exit(pool, 1);
    }
    set_filter(sock, &filter_d);

    spawn_threads(data);
    for(;x<pool->wthread_c;x++){
        pthread_join(pool->write_threads[x], NULL);
        pool->write_threads[x] = 0;
    }
    while(packet_count<expected_responses){
        r = recvfrom(sock, recv_buffer, 4096, 0, NULL, NULL);
        if(r > 0){
            //hex_dump((unsigned char *)recv_buffer, r);
            parse_packet(recv_buffer, r, data->open_flags);
            packet_count += 1;
        }
    }
    shutdown(sock, SHUT_RDWR);
    close(sock);
    return 0;
}

void signal_handler(int signal){
    clean_exit(pool, 130);
}
