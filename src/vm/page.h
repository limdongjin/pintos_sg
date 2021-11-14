#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <stdint.h>
#include <debug.h>
#include <hash.h>
#include "threads/synch.h"

struct page_entry {
    uint32_t vaddr;   // virtual page number
    uint32_t paddr;   // physical page number
    uint32_t pid;
    struct thread *t;
    bool disk;
    bool writable;

    struct hash_elem elem;
    int32_t swap_idx;

    bool is_pinned;
};

struct lock page_lock;
void *frame_for_swap;

void init_page_table ();
void insert_page (void *va, void *pa, bool writable);
bool delete_page (void *va, uint32_t pid);

bool delete_pages_by_ (uint32_t pid);
bool page_evict_frame ();
void page_set_swap (void *va, void *pa, uint32_t pid);
void pinning_buffers (void *buffer, unsigned size);
void unpinning_buffers (void *buffer, unsigned size);
uint32_t calc_page_number (void *);
struct page_entry *get_page_by_ (void *va, uint32_t pid);

#endif