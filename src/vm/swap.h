#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <stdint.h>
#include <debug.h>
#include <bitmap.h>
#include "devices/block.h"

struct block *swap_block;
struct lock swap_lock;
bool *is_swapped;

void swap_init ();
void swap_in (void *upage, uint32_t idx);
uint32_t swap_out (void *frame);
void swap_free (uint32_t swap_idx);

#endif //PINTOS_SG_SWAP_H