#include "../include/memory.h"

extern results_d *results;

void clean_exit(mem_obj *mem, int ret){
    if(mem->rx_ring) munmap(mem->rx_ring, mem->rx_ring_size);
    if(mem->recv_fd > 0) close(mem->recv_fd);
    if(mem->write_fd > 0) close(mem->write_fd);
    if(ret == 130) display_results(results);
    free_ptr_list(mem->ptrs);
    free(mem);
    exit(ret);
}

mem_obj *alloc_mem_obj(mem_obj *mem){
    mem = (mem_obj *)malloc(sizeof(mem_obj));
    if(mem != NULL){
        mem->allocations = 0;
        mem->recv_fd = -1;
        mem->write_fd = -1;
        mem->allocated = 0;
        mem->freed = 0;
        if((mem->ptrs = (ptr_list *)malloc(sizeof(ptr_list))) != NULL){
            mem->ptrs->prev = NULL;
            mem->ptrs->ptr = NULL;
            mem->ptrs->next = NULL;
        }
    }
    return mem;
}

/* allocates space for the new pointer being appended to the array */
void *add_allocation(mem_obj *p, void *ptr, short size){
    ptr_list *x;
    x = p->ptrs;
    while(x->next != NULL){
        x = x->next;
    }
    x->next = (ptr_list *)malloc(sizeof(ptr_list));
    if(x->next != NULL){
        x->next->prev = x;
        x->next->ptr = ptr;
        x->next->size = size;
        x->next->next = NULL;
        p->allocated += size;
        p->allocations += 1;
        return x->next;
    }
    return NULL;
}

int get_ptr_index(ptr_list *p, void *ptr){
    ptr_list *x;
    int ret = 0;
    x = p;
    while(x != NULL){
        if(x->ptr == ptr) return ret;
        ret += 1;
        x = x->next;
    }
    return -1;
}

ptr_list *ptr_via_index(ptr_list *p, void *ptr){
    ptr_list *x;
    x = p;
    while(!x){
        if(x->ptr == ptr) return x;
        x = x->next;
    }
    return NULL;
}

int remove_allocation(mem_obj *p, int index){
    ptr_list *x, *y=NULL, *z=NULL;
    int i = 0;
    x = p->ptrs;
    while(x != NULL){
        if(index == i){
            y = x->prev;
            z = x->next;
            if(y!=NULL) y->next = z;
            if(z!=NULL) z->prev = y;
            p->allocated -= x->size;
            p->allocations -= 1;
            p->freed += x->size;
            if(x->ptr) free(x->ptr);
            x->ptr = NULL;
            free(x);
            return 0;
        }
        x = x->next;
        i += 1;
    }
    return -1;
}

void free_ptr_list(ptr_list *ptr){
    ptr_list *x, *y;
    x = ptr;
    while(x != NULL){
        y = x;
        x = x->next;
        if(y->ptr) free(y->ptr);
        y->ptr = NULL;
        free(y);
    }
    return;
}

void display_stats(mem_obj *p){
    printf("\nMemory mem @ %p\n", (void *)p);
    printf("    Total No. of allocations: %d\n", p->allocations);
    printf("    Memory currently allocated: %d Bytes\n", p->allocated);
    printf("    Memory freed: %d Bytes\n", p->freed);
    return;
}
