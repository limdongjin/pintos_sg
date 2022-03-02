/*
#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "vm/page.h"

void lru_list_init (void);
void add_page_to_lru_list (struct page *);
struct page *find_page_from_lru_list (void *);
void del_page_from_lru_list (struct page *);

struct page *get_victim (void);

#endif
*/
/*
#ifndef VM_FRAME_H
#define VM_FRAME_H

void *cur_frame;

void pinning (void *buffer, unsigned size);
void unpinning (void *buffer, unsigned size);
bool evict_frame(void);

#endif*//*

