/*
#include "vm/swap.h"
#include <bitmap.h>
#include "threads/synch.h"
#include "devices/block.h"
#include "threads/vaddr.h"
#include "threads/interrupt.h"

struct lock swap_lock;
struct bitmap *swap_bitmap;

void
swap_init (size_t size)
{
    lock_init (&swap_lock);
    swap_bitmap = bitmap_create (size);
}

extern struct lock file_lock;

void
swap_in (size_t used_index, void *kaddr)
{
    struct block *swap_block;
    swap_block = block_get_role (BLOCK_SWAP);

    if (used_index-- == 0)
        NOT_REACHED ();

    lock_acquire (&file_lock);
    lock_acquire (&swap_lock);

    ASSERT (pg_ofs (kaddr) == 0);

    used_index <<= 3;
    int i;
    for (i = 0; i < 8; i++)
        block_read (swap_block, used_index + i, kaddr + BLOCK_SECTOR_SIZE * i);
    used_index >>= 3;

    bitmap_set_multiple (swap_bitmap, used_index, 1, false);
    ASSERT (pg_ofs (kaddr) == 0);

    lock_release (&swap_lock);
    lock_release (&file_lock);
}

void swap_clear (size_t used_index)
{
    if (used_index-- == 0)
        return;
    lock_acquire (&swap_lock);
    bitmap_set_multiple (swap_bitmap, used_index, 1, false);
    lock_release (&swap_lock);
}

size_t
swap_out (void *kaddr)
{
    struct block *swap_block;
    swap_block = block_get_role (BLOCK_SWAP);

    lock_acquire (&file_lock);
    lock_acquire (&swap_lock);

    ASSERT (pg_ofs (kaddr) == 0);
    size_t swap_index;
    swap_index = bitmap_scan_and_flip (swap_bitmap, 0, 1, false);
    if (BITMAP_ERROR == swap_index)
    {
        NOT_REACHED();
        return BITMAP_ERROR;
    }
    swap_index <<= 3;
    int i;
    for (i = 0; i < 8; i++)
        block_write (swap_block, swap_index + i, kaddr + BLOCK_SECTOR_SIZE * i);
    swap_index >>= 3;

    ASSERT (pg_ofs (kaddr) == 0);

    lock_release (&swap_lock);
    lock_release (&file_lock);

    return swap_index + 1;
}

*/
/*
#include "swap.h"
#include "vm/frame.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/interrupt.h"
#include "vm/page.h"
#include <stdlib.h>
#include <string.h>

#define SWAP_SIZE (block_size (swap_block) / (PGSIZE/BLOCK_SECTOR_SIZE))

*//*

*/
/* Definitions of Functions of vm/swap.h *//*
*/
/*


void swap_init (void) {
    int i;
    swap_block = block_get_role (BLOCK_SWAP);
    if (swap_block == NULL) PANIC ("swap_init fail");

    is_swapped = malloc (SWAP_SIZE);
    memset(is_swapped, false, SWAP_SIZE);
    lock_init (&swap_lock);
}

// frame -> disk
uint32_t swap_out (void *frame) {
    int i;
    uint32_t swap_idx;
    ASSERT (is_kernel_vaddr (frame));

    lock_acquire (&swap_lock);

    for (swap_idx = 0;
         swap_idx < SWAP_SIZE && is_swapped[swap_idx];
         swap_idx++) {}
    if (swap_idx < SWAP_SIZE && !is_swapped[swap_idx])
        is_swapped[swap_idx] = true;

    for (i = 0; i < (PGSIZE / BLOCK_SECTOR_SIZE); i++)
        block_write (swap_block,
                     swap_idx * (PGSIZE / BLOCK_SECTOR_SIZE) + i,
                     frame + i * BLOCK_SECTOR_SIZE);

    lock_release (&swap_lock);
    return swap_idx;
}

// disk -> frame
void swap_in (void *va, uint32_t swap_idx) {
    void* pa;
    struct page_entry *page;
    int i;

    ASSERT (is_user_vaddr (va));
    while ((pa = palloc_get_page(PAL_USER)) == NULL)
        evict_frame();

    page = get_page_by_(va, thread_tid());
    ASSERT (page != NULL && pa != NULL);

    lock_acquire (&swap_lock);

    for (i = 0; i < (PGSIZE / BLOCK_SECTOR_SIZE); i++)
        block_read (swap_block,
                    i + swap_idx * (PGSIZE / BLOCK_SECTOR_SIZE),
                    i * BLOCK_SECTOR_SIZE + pa);

    pagedir_set_page(thread_current()->pagedir,
                     va, pa, page->writable);
    set_page_for_swap_in(va, pa, thread_tid());
    is_swapped[swap_idx] = false;

    lock_release (&swap_lock);
}

void swap_free (uint32_t swap_idx) {
    lock_acquire (&swap_lock);
    is_swapped[swap_idx] = false;
    lock_release (&swap_lock);
}*//*

