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

// TODO macro naming
#define SPP (PGSIZE / BLOCK_SECTOR_SIZE)
#define SWAP_IDX_SIZE (block_size (swap_block) / SPP)

void swap_init () {
    int i;
    swap_block = block_get_role (BLOCK_SWAP);
    if (swap_block == NULL) PANIC ("swap_init fail");

    is_swapped = malloc (SWAP_IDX_SIZE);
    memset(is_swapped, false, SWAP_IDX_SIZE);
    lock_init (&swap_lock);
}

// frame -> disk
uint32_t swap_out (void *frame) {
    int i;
    uint32_t swap_idx;
    ASSERT (is_kernel_vaddr (frame));

    lock_acquire (&swap_lock);

    for (swap_idx = 0;
         swap_idx < SWAP_IDX_SIZE && is_swapped[swap_idx];
         swap_idx++) {}
    if (swap_idx < SWAP_IDX_SIZE && !is_swapped[swap_idx])
        is_swapped[swap_idx] = true;

    for (i = 0; i < SPP; i++)
        block_write (swap_block,
                     swap_idx * SPP + i,
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

    for (i = 0; i < SPP; i++)
        block_read (swap_block,
                    swap_idx * SPP + i,
                    pa + i * BLOCK_SECTOR_SIZE);

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
}