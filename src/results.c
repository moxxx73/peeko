#include "../include/results.h"

results_d *init_results(void){
    results_d *ret;
    ret = (results_d *)malloc(RESULTS_SIZ);
    if(ret){
        ret->closed_ports = NULL;
        ret->open_ports = NULL;
        ret->number_of_open = 0;
        ret->number_of_closed = 0;
        ret->packets_recvd = 0;
        ret->dropped = 0;
        ret->packets_sent = 0;
        return ret;
    }
    return NULL;
}

int add_open_port(results_d *results, short port){
    short amount;
    if(!results){
        return -1;
    }
    amount = results->number_of_open;
    amount += 1;
    results->open_ports = (short *)realloc(results->open_ports, (amount*2));
    if(!results->open_ports) return -1;
    results->open_ports[(amount-1)] = port;
    results->number_of_open = amount;
    return 0;
}

int add_closed_port(results_d *results, short port){
    short amount;
    if(!results){
        return -1;
    }
    amount = results->number_of_closed;
    amount += 1;
    results->closed_ports = (short *)realloc(results->closed_ports, (amount*2));
    if(!results->closed_ports) return -1;
    results->closed_ports[(amount-1)] = port;
    results->number_of_closed = amount;
    return 0;
}

void display_results(results_d *results){
    int x=0;
    printf("%s[+]%s Done scanning\n", GREENC, RESET);
    if(results->number_of_open){
        for(;x<results->number_of_open;x++){
            printf("    Port %hu is open\n", results->open_ports[x]);
        }
    }
    return;
}

void asc_sort(void){
    return;
}

void desc_sort(void){
    return;
}
