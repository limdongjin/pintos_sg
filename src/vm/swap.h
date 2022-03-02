/*#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <stddef.h>

void swap_init (size_t);
void swap_in (size_t, void *);
void swap_clear (size_t);
size_t swap_out (void *);

#endif*/
/*
#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <debug.h>
#include "devices/block.h"
#include <stdint.h>
#include <bitmap.h>

bool *is_swapped;
struct block *swap_block;
struct lock swap_lock;

void swap_init (void);
void swap_in (void *va, uint32_t idx);
uint32_t swap_out (void *frame);

void swap_free (uint32_t swap_idx);

#endif
*/
