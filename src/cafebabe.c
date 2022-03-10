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

void signal_handler(int signal){
    printf("\n");
    clean_exit(mem, 130);
}

void cafebabe_main(cafebabe *args, char *name, parse_r *lst, char resolve){
    int r=0;
    int method=0;
    char src_str[INET_ADDRSTRLEN];
    scan_data *scan_info = NULL;
    stack *stck = NULL;
    memset(src_str, 0, INET_ADDRSTRLEN);

    /* resolve hostname -> ASCII IPv4 Address */
    if(resolve){
        r = resolve_name(name, args->addr);
        if(!r){
            printf("[%sERROR%s] resolve_name(): %s\n", REDC, RESET, hstrerror(h_errno));
            exit(1);
        }
    }else memcpy(args->addr, name, INET_ADDRSTRLEN);

    /* if we're using a scan that isn't the HANDSHAKE_SCAN        */
    /* then we're constructing our own IP headers and will need   */
    /* and IP address to use -> so we fetch the IP address of the */
    /* working interface                                          */
    if(!(args->method&HANDSHAKE_SCAN)){
        if(!getifaddr(args->ifn, src_str)){
            err_msg("getifaddr()");
            exit(1);
        }
        printf("[%sINFO%s] Operating on interface: %s (%s)\n", BLUEC, RESET, args->ifn, src_str);
    }
    printf("[%sINFO%s] Scanning Target %s\n", BLUEC, RESET, name);

    /* mem_obj and related memory operations are all defined in cafebabe/include/memory.h */
    if((mem = alloc_mem_obj(mem)) == NULL){
        err_msg("alloc_mem_obj()");
        free(lst);
        free(args);
        exit(1);
    }
    /* append allocated memory to linked list */
    add_allocation(mem, (void *)lst, sizeof(parse_r));
    add_allocation(mem, (void *)args, CAFEBABE_SIZ);
    add_allocation(mem, (void *)args->ifn, IF_NAMESIZE);
    add_allocation(mem, (void *)args->addr, INET_ADDRSTRLEN);

    /* defined in cafebabe/include/net.h */
    scan_info = (scan_data *)malloc(SCAN_DATA_SIZ);
    if(!scan_info){
        printf("[%sERROR%s] Failed to initialise scan data\n", REDC, RESET);
        clean_exit(mem, 1);
    }
    add_allocation(mem, (void *)scan_info, SCAN_DATA_SIZ);

    /* allocate stack header                */
    /* with a stack the same size           */
    /* as the list of ports in parse_r *lst */
    stck = alloc_stack(lst->llen);
    if(stck == NULL){
        printf("[%sERROR%s] Failed to allocate memory for queue\n", REDC, RESET);
        clean_exit(mem, 1);
    }
    /* defined above cafebabe_main takes a list     */
    /* of ports and fills the stack with said ports */
    if(fill_stack(lst, stck) < 0){
        printf("[%sERROR%s] List is larger than stack size\n", REDC, RESET);
        clean_exit(mem, 1);
    }
    remove_allocation(mem, get_ptr_index(mem->ptrs, (void *)lst));
    add_allocation(mem, (void *)stck, STACK_HDR_SIZ);

    /* global struct used at the end of a scan       */
    /* whether it finished naturally or by interrupt */
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
    /* including the call to inet_pton above, the next         */
    /* few lines up to signal() migrate data from the cafebabe */
    /* structure to the scan_data structure allocated above    */
    inet_pton(AF_INET, src_str, &scan_info->src_ip);
    scan_info->sport = args->sport;
    strncpy(scan_info->interface_name, args->ifn, IF_NAMESIZE);
    scan_info->dports = stck;
    scan_info->family = AF_INET;
    method = args->method;

    /* if the user wants to cancel the scan early */
    /* then this has to handled cleanly           */
    signal(SIGINT, signal_handler);

    scan_mgr(scan_info, method);
    display_results(results);
    
    clean_exit(mem, 0);
}
