#include "page.h"
//#include "frame.h"
#include "swap.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "threads/interrupt.h"

struct hash page_table;

static uint32_t calc_page_idx (const struct page_entry *page);
static bool pinning_and_swapin (void *va, uint32_t pid);
static struct hash_elem *get_hash_elem (void *va, uint32_t pid);
static bool page_less_func (const struct hash_elem *a,
                            const struct hash_elem *b, void *aux);
static unsigned page_hash_func (const struct hash_elem *a,
                                void *aux);

static bool
page_less_func (const struct hash_elem *a,
                     const struct hash_elem *b, void *aux) {
   return calc_page_idx(hash_entry(a, struct page_entry, elem))
           < calc_page_idx(hash_entry(b, struct page_entry, elem));
}

static unsigned
page_hash_func (const struct hash_elem *a, void *aux) {
    uint32_t idx = calc_page_idx(hash_entry(a,
                                        struct page_entry,
                                                elem));
    return hash_bytes (&idx, sizeof idx);
}

void
init_page_table () {
    hash_init (&page_table, &page_hash_func, &page_less_func, NULL);
    frame_for_swap = palloc_get_page (PAL_USER);
    lock_init (&page_lock);
}

uint32_t calc_page_number (void* addr) {
    return ((uint32_t)addr& 0xfffff000)>> 12;
}

struct page_entry *get_page_by_ (void *va, uint32_t pid) {
    struct page_entry* ret = NULL;
    struct hash_elem* he;
    lock_acquire (&page_lock);
    he = get_hash_elem (va, pid);
    lock_release (&page_lock);

    if(he != NULL)
        ret = hash_entry (he, struct page_entry, elem);

    return ret;
}

static struct hash_elem*
get_hash_elem (void *va, uint32_t pid) {
    struct page_entry page;
    page.vaddr = calc_page_number(va);
    page.pid = pid;
    return hash_find(&page_table, &page.elem);
}

static struct page_entry*
make_page_by_(void* va, void* pa, bool writable);
static struct page_entry*
make_page_by_(void* va, void* pa, bool writable){
            struct page_entry* page;
            ASSERT (va != NULL);
            page = malloc (sizeof (struct page_entry));
            ASSERT (page != NULL);
    page->is_pinned = false;
    page->writable = writable;
    page->vaddr = calc_page_number(va);
    page->pid = thread_tid ();
    page->elem.list_elem.next = NULL;
    page->elem.list_elem.prev = NULL;
    page->t = thread_current();
            if(pa == frame_for_swap) {
                page->paddr = 0;
                page->swap_idx = swap_out (pa);  // knpage는 load_segment에서 채워짐
                page->disk = true;
            }else{
                page->paddr = calc_page_number(pa);
                page->swap_idx = -1;
                page->disk = false;
            }

            return page;
}
void insert_page (void *va, void *pa, bool writable) {
    struct page_entry* page = make_page_by_(va, pa, writable);

    lock_acquire (&page_lock);
    if (hash_insert(&page_table, &(page->elem)) == NULL) {
        ASSERT (page);
    }
    lock_release (&page_lock);
}

bool delete_page (void *va, uint32_t pid) {
    lock_acquire (&page_lock);
    struct hash_elem *target = get_hash_elem (va, pid);
    lock_release (&page_lock);

    if(target == NULL) return false;

    lock_acquire (&page_lock);
    hash_delete (&page_table, target);
    lock_release (&page_lock);

    free (hash_entry (target, struct page_entry, elem));
    return true;
}

bool delete_pages_by_ (uint32_t pid) {
    lock_acquire (&page_lock);
    struct page_entry* page;
    struct hash_elem* he;
    while (1) {
        struct hash_iterator it;
        hash_first (&it, &page_table);
        while(hash_next(&it) &&
            (page = hash_entry (hash_cur(&it),
                                struct page_entry, elem))->pid
                                       != pid){}
        if(page->pid != pid) break;
        if (page->swap_idx != -1) swap_free (page->swap_idx);

        he = hash_cur(&it);
        hash_delete (&page_table, &page->elem);
        free (hash_entry (he, struct page_entry, elem));
    }
    lock_release (&page_lock);
    return true;
}

bool page_evict_frame () {
    struct hash_iterator it;
    struct page_entry *page = NULL;

    bool flag = false;
    while(!flag){
        hash_first(&it, &page_table);
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

void
page_set_swap (void *va, void *pa, uint32_t pid) {
    ASSERT (get_hash_elem (va, pid) != NULL);
    struct page_entry *page = hash_entry(get_hash_elem(va, pid),
                                    struct page_entry,
                                            elem);
    page->swap_idx = -1;
    page->paddr = calc_page_number(pa);
}

static uint32_t
calc_page_idx (const struct page_entry *page) {
    ASSERT (page->pid < 0x1000);
    return ((uint32_t)(page->vaddr) << 12) + page->pid;
}

static bool
pinning_and_swapin (void *va, uint32_t pid) {
    struct page_entry *page = get_page_by_(va, pid);
   // lock_acquire (&swap_lock);
   // lock_release (&swap_lock);
    if (page == NULL) return false;
    page->is_pinned = true;
    if (page->paddr != 0) return true;

    swap_in (va, page->swap_idx);
    return true;
}

void pinning_buffers (void *buffer, unsigned size) {
    uint32_t pid = thread_tid();
    uint32_t buf = ((uint32_t) buffer >>12)<<12;
    int siz = size + (uint32_t)buffer-buf;

    for(;siz > 0;buf+=PGSIZE,siz-=PGSIZE)
        pinning_and_swapin((void*)buf, pid);
}

void unpinning_buffers (void *buffer, unsigned size) {
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