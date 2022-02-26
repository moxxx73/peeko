#include "../include/cafebabe.h"

extern char verbose;

mem_obj *mem = NULL;
results_d *results = NULL;

int fill_stack(parse_r *lst, stack *st){
    int i;
    for(i=0;i<lst->llen;i++){
        if(push(st, lst->list[i]) < 0) return -1;
    }
    return 0;
}

void cafebabe_main(cafebabe *args, char *name, parse_r *l, int thread_no, char resolve){
    int r=0;
    int method;
    char src_str[INET_ADDRSTRLEN];
    scan_data *scan_info = NULL;
    stack *stck = NULL;
    if(resolve){
        r = resolve_name(name, args->addr);
        if(!r){
            printf("[%sERROR%s] resolve_name(): %s\n", REDC, RESET, hstrerror(h_errno));
            exit(1);
        }
    }else memcpy(name, args->addr, INET_ADDRSTRLEN);

    /* check whether we are doing a raw packet scan*/
    /* -in which case we'll need to know what interface */
    /* to work with */
    if(!(args->method&HANDSHAKE_SCAN)){
        if(!getifaddr(args->ifn, src_str)){
            err_msg("getifaddr()");
            exit(1);
        }
        printf("[%sINFO%s] Operating on interface: %s (%s)\n", BLUEC, RESET, args->ifn, src_str);
    }
    printf("[%sINFO%s] Scanning Target %s\n", BLUEC, RESET, name);

    if((mem = alloc_mem_obj(mem)) == NULL){
        err_msg("alloc_mem_obj()");
        free(l);
        free(args);
        exit(1);
    }
    add_allocation(mem, (void *)l, sizeof(parse_r));
    add_allocation(mem, (void *)args, CAFEBABE_SIZ);
    add_allocation(mem, (void *)args->ifn, IF_NAMESIZE);
    add_allocation(mem, (void *)args->addr, INET_ADDRSTRLEN);

    scan_info = (scan_data *)malloc(SCAN_DATA_SIZ);
    if(!scan_info){
        printf("[%sERROR%s] Failed to initialise scan data\n", REDC, RESET);
        clean_exit(mem, 1);
    }
    scan_info->thread_c = thread_no;
    add_allocation(mem, (void *)scan_info, SCAN_DATA_SIZ);

    stck = alloc_stack(l->llen);
    if(stck == NULL){
        printf("[%sERROR%s] Failed to allocate memory for queue\n", REDC, RESET);
        clean_exit(mem, 1);
    }
    if(fill_stack(l, stck) < 0){
        printf("[%sERROR%s] List is larger than stack size\n", REDC, RESET);
        clean_exit(mem, 1);
    }
    remove_allocation(mem, get_ptr_index(mem->ptrs, (void *)l));
    add_allocation(mem, (void *)stck, STACK_HDR_SIZ);

    if((results = init_results()) == NULL){
        printf("[%sERROR%s] Failed to allocate memory for result structure\n", REDC, RESET);
        clean_exit(mem, 1);
    }
    add_allocation(mem, (void *)results, RESULTS_SIZ);
    results->ip_string = (char *)malloc(INET_ADDRSTRLEN);
    if(!results->ip_string){
        err_msg("malloc()");
        clean_exit(mem, 1);
    }
    memcpy(results->ip_string, args->addr, INET_ADDRSTRLEN);

    r = inet_pton(AF_INET, args->addr, &scan_info->dst_ip);
    if(!r){
        printf("[%sERROR%s] Invalid target address\n", REDC, RESET);
        clean_exit(mem, 1);
    }
    inet_pton(AF_INET, src_str, &scan_info->src_ip);
    scan_info->sport = args->sport;
    strncpy(scan_info->interface_name, args->ifn, IF_NAMESIZE);
    scan_info->dports = stck;
    scan_info->family = AF_INET;
    method = args->method;

    signal(SIGINT, signal_handler);

    scan_mgr(scan_info, method);

    display_results(results);
    clean_exit(mem, 0);
}
