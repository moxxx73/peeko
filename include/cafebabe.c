#include "cafebabe.h"

extern char verbose;
/*
extern char debug;
extern char underline[];
extern char reset[];
*/

pool_d *pool = NULL;
results_d *results = NULL;

int fill_stack(parse_r *lst, stack *st){
    int i;
    for(i=0;i<lst->llen;i++){
        if(push(st, lst->list[i]) < 0) return -1;
    }
    return 0;
}

/* the "staging area", just does a lot of the setup such as */
/* creating the main data pool and our result structure in the heap */
int cafebabe_main(cafebabe *args, char *name, parse_r *l, int t){
    int r=0;
    char src_str[INET_ADDRSTRLEN];
    scan_p *scan_args = NULL;
    stack *stck = NULL;
    r = resolve_name(name, args->addr);
    if(r != 0){
        return 1;
    }

    if(getifaddr(args->ifn, src_str) < 0){
        printf("[!] Failed to fetch interface address\n");
        exit(1);
    }
    printf("Operating on interface: %s (%s)\n", args->ifn, src_str);

    if((pool = create_pool(pool)) == NULL){
        printf("Failed to allocate pool memory\n");
        free(l);
        free(args);
        exit(1);
    }
    add_allocation(pool, (void *)l, sizeof(parse_r), "listp\0");
    add_allocation(pool, (void *)args, SCAN_SIZ, "scan_args\0");
    add_allocation(pool, (void *)args->ifn, IFNAMSIZ, "interface\0");
    add_allocation(pool, (void *)args->addr, INET_ADDRSTRLEN, "address\0");

    scan_args = (scan_p *)malloc(sizeof(scan_p));
    if(scan_args == NULL){
        printf("Failed to initialise scan_p structure\n");
        clean_exit(pool, 1);
    }
    /* if(debug) printf("%s[DEBUG]%s Allocated scan_p @ %p\n", underline, reset, (void *)scan_args); */
    add_allocation(pool, (void *)scan_args, SCAN_SIZ, "scan-args\0");

    stck = alloc_stack(l->llen);
    if(stck == NULL){
        printf("Failed to allocate memory for queue\n");
        clean_exit(pool, 1);
    }
    if(fill_stack(l, stck) < 0){
        // handle_err();
        printf("[!] List is larger than stack size\n");
        return -1;
    }
    remove_allocation(pool, get_ptr_index(pool->ptrs, (void *)l));
    /*
    if(debug){
        printf("%s[DEBUG]%s Initialised queue @ %p\n", underline, reset, (void *)q);
        printf("        Data allocated @ %p\n", (void *)q->data);
        printf("        Length: %d\n", q->size);
    }
    */
    add_allocation(pool, (void *)stck, STACK_HDR_SIZ, "stk-hdr\0");

    if((results = init_results()) == NULL){
        printf("Failed to allocate memory for result structure\n");
        clean_exit(pool, 1);
    }
    add_allocation(pool, (void *)results, RESULTS_SIZ, "results\0");

    inet_pton(AF_INET, args->addr, &scan_args->dst);
    inet_pton(AF_INET, src_str, &scan_args->src);
    scan_args->sport = args->sport;
    scan_args->ifn = args->ifn;
    scan_args->stk = stck;
    scan_args->method = args->method;
    scan_args->family = AF_INET;

    signal(SIGINT, signal_handler);
    /*if(scan_args->method > 0){
        start_sniffer(scan_args);
        start_writer(scan_args);
        pthread_join(pool->write_thread, NULL);
        pthread_join(pool->recv_thread, NULL);
    }*/
    clean_exit(pool, 0);
    return 0;
}
