#include "page.h"
#include "frame.h"
#include "swap.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "threads/interrupt.h"

static bool pin_and_swap (void *va, uint32_t pid);
static bool
pin_and_swap (void *va, uint32_t pid) {
    struct page_entry *page = get_page_by_(va, pid);
    if (page == NULL) return false;
    page->is_pinned = true;
    if (page->paddr != 0) return true;

    swap_in (va, page->swap_idx);
    return true;
}

void pinning (void *buffer, unsigned size) {
    uint32_t pid = thread_tid();
    uint32_t buf = ((uint32_t) buffer >>12)<<12;
    int siz = size + (uint32_t)buffer-buf;

    for(;siz > 0;buf+=PGSIZE,siz-=PGSIZE)
        pin_and_swap((void*)buf, pid);
}

void unpinning (void *buffer, unsigned size) {
    struct page_entry* page;
    uint32_t buf = ((uint32_t)buffer>>12)<< 12;
    int siz = size + (uint32_t) buffer -buf;
    uint32_t pid = thread_tid();

    for(;siz>0;buf+=PGSIZE,siz-=PGSIZE){
        page = get_page_by_(buf, pid);
        ASSERT(page != NULL);
        page->is_pinned = false;
    }
}

bool
evict_frame(void) {
    struct hash_iterator it;
    struct page_entry *page = NULL;

    bool flag = false;
    while(!flag){
        hash_first(&it, get_page_table());
        while(hash_next(&it)){
            page = hash_entry (hash_cur (&it), struct page_entry, elem);
            if (page->is_pinned == false &&
                page->paddr != 0 &&
                thread_get_ticks() % 3 != 0) {
                flag = true;
                break;
            }
        }
    }
    if(!flag) {
        PANIC("evict fail");
        return false;
    }
    page->swap_idx = swap_out(page->paddr << 12);
    pagedir_clear_page (page->t->pagedir, (void*)(page->vaddr << 12));
    palloc_free_page ((void*)(page->paddr << 12));
    page->paddr = 0;
    return true;
}
