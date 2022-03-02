/*
#include "vm/frame.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "threads/thread.h"
#include "threads/interrupt.h"
#include "threads/vaddr.h"

static struct list_elem *get_next_lru_clock (void);

struct list lru_list;
struct lock lru_list_lock;
struct list_elem *lru_clock;

void
lru_list_init (void)
{
    list_init (&lru_list);
    lock_init (&lru_list_lock);
    lru_clock = NULL;
}

void
add_page_to_lru_list (struct page *page)
{
    lock_acquire (&lru_list_lock);
    ASSERT (page->thread);
    ASSERT (page->thread->magic == 0xcd6abf4b);
    list_push_back (&lru_list, &page->lru);
    lock_release (&lru_list_lock);
}

struct page *
find_page_from_lru_list (void *kaddr)
{
    ASSERT (lock_held_by_current_thread (&lru_list_lock));
    ASSERT (pg_ofs (kaddr) == 0);

    struct list_elem *e;
    for (e = list_begin (&lru_list);
         e != list_end (&lru_list);
         e = list_next (e))
    {
        struct page *page = list_entry (e, struct page, lru);
        ASSERT (page);
        if (page->kaddr == kaddr)
            return page;
    }
    return NULL;
}

void
del_page_from_lru_list (struct page *page)
{
    ASSERT (lock_held_by_current_thread (&lru_list_lock));
    ASSERT (page);
    if (lru_clock == &page->lru)
    {
        lru_clock = list_remove (lru_clock);
    }
    else
    {
        list_remove (&page->lru);
    }
}

static struct list_elem *
get_next_lru_clock (void)
{
    ASSERT (lock_held_by_current_thread (&lru_list_lock));
    if (lru_clock == NULL || lru_clock == list_end (&lru_list))
    {
        if (list_empty (&lru_list))
            return NULL;
        else
            return (lru_clock = list_begin (&lru_list));
    }
    lru_clock = list_next (lru_clock);
    if (lru_clock == list_end (&lru_list))
        return get_next_lru_clock ();
    return lru_clock;
}

struct page *
get_victim (void)
{
    struct page *page;
    struct list_elem *e;

    ASSERT (lock_held_by_current_thread (&lru_list_lock));

    e = get_next_lru_clock ();
    ASSERT (e != NULL);
    page = list_entry (e, struct page, lru);
    ASSERT (page);
    ASSERT (page->thread);
    ASSERT (page->thread->magic == 0xcd6abf4b);
    ASSERT (page->vme);

    while (page->vme->pinned ||
           pagedir_is_accessed (page->thread->pagedir, page->vme->vaddr))
    {
        pagedir_set_accessed (page->thread->pagedir, page->vme->vaddr, false);
        e = get_next_lru_clock ();
        ASSERT (e != NULL);
        page = list_entry (e, struct page, lru);
        ASSERT (page);
        ASSERT (page->thread);
        ASSERT (page->thread->magic == 0xcd6abf4b);
        ASSERT (page->vme);
    }
    return page;
}

*/
/*
#include "page.h"
#include "frame.h"
#include "swap.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "threads/interrupt.h"

*//*

*/
/* Declarations of Helper Functions *//*
*/
/*


static bool pin_and_swap (void *va, uint32_t pid);

*//*

*/
/* Definitions of Functions of vm/frame.h *//*
*/
/*


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

*//*

*/
/* Definitions of Helper Functions *//*
*/
/*


static bool
pin_and_swap (void *va, uint32_t pid) {
    struct page_entry *page = get_page_by_(va, pid);
    if (page == NULL) return false;
    page->is_pinned = true;
    if (page->paddr != 0) return true;

    swap_in (va, page->swap_idx);
    return true;
}*//*

