#include "page.h"
//#include "frame.h"
#include "swap.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "threads/interrupt.h"

struct hash pt;
bool pt_less_func (const struct hash_elem *a,
                   const struct hash_elem *b, void *aux) {
    uint64_t aidx = page_get_idx(hash_entry(a, struct page_entry, elem));
    uint64_t bidx = page_get_idx(hash_entry(b, struct page_entry, elem));
    if (aidx < bidx)    return true;
    else                return false;
}

unsigned pt_hash_func (const struct hash_elem *e, void *aux) {
    uint32_t idx = page_get_idx(hash_entry(e, struct page_entry, elem));
    return hash_bytes (&idx, sizeof idx);
}

void page_table_init () {
    hash_init (&pt, &pt_hash_func, &pt_less_func, NULL);
    frame_for_swap = palloc_get_page (PAL_USER);
    lock_init (&page_lock);
}

uint32_t get_page_number (void* addr) {
    return ((uint32_t)addr & 0xfffff000) >> 12;
}

struct page_entry *page_get_entry (void *vaddr, uint32_t pid) {
    lock_acquire (&page_lock);
    struct hash_elem *he = get_hash_elem (vaddr, pid);
    lock_release (&page_lock);
    if (he != NULL)
        return hash_entry (he, struct page_entry, elem);
    else
        return NULL;
}

struct hash_elem *get_hash_elem (void *vaddr, uint32_t pid) {
    struct page_entry pte;
    pte.vpn = get_page_number (vaddr);
    pte.pid = pid;
    return hash_find(&pt, &pte.elem);
}

void page_insert (void *upage, void *knpage, bool writable) {
    ASSERT (upage != NULL);
    struct page_entry *pte = malloc (sizeof (struct page_entry));
    ASSERT (pte != NULL);

    if (knpage != frame_for_swap) {         // knpage : page.h에 전역변수로 선언
        pte->ppn = get_page_number (knpage);
        pte->swap_idx = -1;
        pte->is_on_disk = false;
    }
    else {
        pte->ppn = 0;
        pte->swap_idx = swap_out (knpage);  // knpage는 load_segment에서 채워짐
        pte->is_on_disk = true;
    }
    pte->pinned = false;
    pte->vpn = get_page_number (upage);
    pte->pid = thread_tid ();
    pte->writable = writable;
    pte->elem.list_elem.next = NULL;
    pte->elem.list_elem.prev = NULL;
    pte->t = thread_current();
    lock_acquire (&page_lock);
    if (hash_insert(&pt, &(pte->elem)) == NULL)
        ASSERT (pte);
    lock_release (&page_lock);
    return;
}

bool page_delete (void *upage, uint32_t pid) {
    lock_acquire (&page_lock);
    struct hash_elem *target = get_hash_elem (upage, pid);
    lock_release (&page_lock);
    if (target != NULL) {
        lock_acquire (&page_lock);
        hash_delete (&pt, target);
        lock_release (&page_lock);
        free (hash_entry (target, struct page_entry, elem));
        return true;
    }
    return false;
}

bool page_destroy_by_pid (uint32_t pid) {
    lock_acquire (&page_lock);
    bool deleted = true;
    while (deleted == true) {
        deleted = false;
        struct hash_iterator i;

        hash_first (&i, &pt);
        while (hash_next (&i)) {
            struct page_entry *pte = hash_entry (hash_cur (&i), struct page_entry, elem);
            if (pte->pid == pid) {
                if (pte->swap_idx != -1) {
                    swap_free (pte->swap_idx);
                }
                struct hash_elem *h = hash_cur (&i);
                hash_delete (&pt, &pte->elem);
                free (hash_entry (h, struct page_entry, elem));
	//	palloc_free_page(hash_entry(h, struct page_entry, elem));
                deleted = true;
                break;
            }
        }
    }
    lock_release (&page_lock);
    return true;
}

bool page_evict_frame () {  // randomly evict
    struct hash_iterator i;
    struct thread *cur = thread_current();
    struct page_entry *pte = NULL;

    while (1) {
        hash_first (&i, &pt);
        while (hash_next (&i)) {
            pte = hash_entry (hash_cur (&i), struct page_entry, elem);
            if (pte->pinned == false && pte->ppn != 0) {
                if (thread_get_ticks () % 3 == 0)
                    continue;
                pte->swap_idx = swap_out (pte->ppn << 12);
                pagedir_clear_page (pte->t->pagedir, (void *)(pte->vpn << 12));
                palloc_free_page ((void *)(pte->ppn << 12));
                pte->ppn = 0;
                return true;
            }
        }
    }
    PANIC ("page_evict_frame fail!");
}

void page_set_swap (void *upage, void *kpage, uint32_t pid) {
    struct hash_elem *e = get_hash_elem (upage, pid);
    ASSERT (e != NULL);
    struct page_entry *pte = hash_entry (e, struct page_entry, elem);
    pte->ppn = get_page_number (kpage);
    pte->swap_idx = -1;
}
/*
void page_set_all_accessd_false () {
    lock_acquire (&page_lock);
    struct thread *cur = thread_current();
    struct hash_iterator i;
    hash_first (&i, &pt);
    while (hash_next (&i)) {
        struct page_entry *pte = hash_entry (hash_cur (&i), struct page_entry, elem);
        pagedir_set_accessd (cur->pagedir, (void *)(pte->vpn << 12), false);
    }
    lock_release (&page_lock);
}*/

uint32_t page_get_idx (const struct page_entry *pte) {
    uint32_t idx = (uint32_t)(pte->vpn);
    idx = idx << 12;
    idx += pte->pid;
    ASSERT (pte->pid < 0x1000);
    return idx;
}

bool page_swap_in_and_pinning (void *upage, uint32_t pid) {
    struct page_entry *pte = page_get_entry (upage, pid);
    lock_acquire (&swap_lock);
    lock_release (&swap_lock);
    if (pte == NULL)
        return false;

    pte->pinned = true;

    if (pte->ppn != 0)
        return true;

    swap_in (upage, pte->swap_idx);
    return true;
}

void page_pinning_buffers (void *buffer_, unsigned size_) {
    uint32_t buffer = ((uint32_t) buffer_ >> 12) << 12;
    int size = size_ + (uint32_t) buffer_ - buffer;
    uint32_t pid = thread_tid();
    while (size > 0) {
        page_swap_in_and_pinning ((void*) buffer, pid);
        buffer += PGSIZE;
        size -= PGSIZE;
    }
}

void page_unpinning_buffers (void *buffer_, unsigned size_) {
    uint32_t buffer = ((uint32_t) buffer_ >> 12) << 12;
    int size = size_ + (uint32_t) buffer_ - buffer;
    uint32_t pid = thread_tid();
    while (size > 0) {
        struct page_entry *pte = page_get_entry (buffer, pid);
        ASSERT (pte != NULL);
        pte->pinned = false;
        buffer += PGSIZE;
        size -= PGSIZE;
    }
}

int page_swap_in_all () {
    struct thread *cur = thread_current();
    struct hash_iterator i;
    void *p;
    int cnt = 0;
    int res  = 0;
    hash_first (&i, &pt);
    while (hash_next (&i)) {
        struct page_entry *pte = hash_entry (hash_cur (&i), struct page_entry, elem);
        if (pte->ppn == 0) {
            is_swapped[pte->swap_idx] = true;
        }

    }
    return res;
}

//#include "vm/page.h"
//#include <stdio.h>
//#include <stdlib.h>
//#include "pagedir.h"
//#include "threads/thread.h"
//#include "threads/palloc.h"
//#include "threads/vaddr.h"
//#include "threads/interrupt.h"
//#include "vm/frame.h"
//#include "swap.h"
//
//static unsigned ptable_hash_func(const struct hash_elem *e, void *aux);
//static bool ptable_less_func(const struct hash_elem* a, const struct hash_elem *b, void *aux);
//static void page_delete_func(struct hash_elem* h, void* aux);
//
//void ptable_init(struct hash *ptable){
//    hash_init(ptable, ptable_hash_func, ptable_less_func, NULL);
//    frame_for_swap = palloc_get_page(PAL_USER);
//    lock_init(&page_lock);
//}
//
//static void page_delete_func(struct hash_elem* h, void* aux){
//    struct page* p = hash_entry(h, struct page, elem);
//    free(p);
//}
//void ptable_destroy(struct hash *ptable){
//    hash_destroy(ptable, page_delete_func);
//}
//static unsigned ptable_hash_func(const struct hash_elem *e, void* aux){
//    struct page* p = hash_entry(e, struct page, elem);
//    return hash_bytes(&p->vaddr, sizeof(p->vaddr));
//}
//static bool ptable_less_func(const struct hash_elem *a, const struct hash_elem *b,  void *aux){
//    return hash_entry(a, struct page, elem)->vaddr <  hash_entry(b, struct page, elem)->vaddr;
//}
//uint32_t get_page_number (void* addr) {
//    return ((uint32_t)addr & 0xfffff000) >> 12;
//}
//bool insert_page(struct hash* ptable, void* vaddr, void *paddr, bool writable){
//    ASSERT(vaddr != NULL);
//    struct page *pte=(struct page*)malloc(sizeof(struct page));
//    ASSERT(pte != NULL);
//    if (paddr != frame_for_swap) {         // knpage : page.h에 >전역변수로 선언
//        pte->paddr = get_page_number (paddr);
//        pte->swap_idx = -1;
//        pte->in_disk = false; // is_on_disk = false
//    }
//    else {
//        pte->paddr = 0;
//        pte->swap_idx = swap_out (paddr);  // knpage는 load_segment에서 채워짐
//        pte->in_disk = true; // is_on_disk = true
//    }
//
//    pte->pinned = false;
//    pte->vaddr = get_page_number (vaddr);
//    pte->pid = thread_tid ();
//    pte->writable = writable;
//    pte->elem.list_elem.next = NULL;
//    pte->elem.list_elem.prev = NULL;
//    pte->t = thread_current();
//    lock_acquire (&page_lock);
//    if (hash_insert(ptable, &(pte->elem)) == NULL)
//        ASSERT (pte);
//    lock_release (&page_lock);
//    return true;
////    page->vaddr=pg_round_down(vaddr);
////    page->paddr=pg_round_down(paddr);
////    page->swap_idx=-1;
////    page->writable=writable;
////    struct thread* cur=thread_current();
////
////    if(!hash_find(ptable, &page->elem))
////        hash_insert(ptable, &page->elem);
////    else
////    {
////        struct page* ptr=page;
////        page=hash_entry(hash_find(ptable, &page->elem), struct page, elem);
////        page->swap_idx=-1;
////        free(ptr);
////    }
////    return true;
//}
////
////bool delete_page_by_vaddr(struct  hash* ptable, void* vaddr){
////    struct page *page= find_page_by_vaddr(ptable, vaddr);
////    if(page!=NULL){
////        hash_delete(ptable, &page->elem);
////        return true;
////    }
////    return false;
////}
//struct hash_elem *get_hash_elem (struct hash* ptable, void* vaddr, uint32_t pid) {
//    struct page pte;
//    pte.vaddr= get_page_number (vaddr);
//    pte.pid = pid;
//    return hash_find(ptable, &pte.elem);
//}
//bool page_delete_by_pid (struct hash* ptable,void *vaddr, uint32_t pid) {
//    lock_acquire (&page_lock);
//    struct hash_elem *target = get_hash_elem (vaddr, pid);
//    lock_release (&page_lock);
//    if (target != NULL) {
//        lock_acquire (&page_lock);
//        hash_delete (ptable, target);
//        lock_release (&page_lock);
//        free (hash_entry (target, struct page, elem));
//        return true;
//    }
//    return false;
//}
//bool page_destroy_by_pid (struct hash* ptable,uint32_t pid) {
//    lock_acquire (&page_lock);
//    bool deleted = true;
//    while (deleted == true) {
//        deleted = false;
//        struct hash_iterator i;
//
//        hash_first (&i, ptable);
//        while (hash_next (&i)) {
//            struct page *pte = hash_entry (hash_cur (&i), struct page, elem);
//            if (pte->pid == pid) {
//                if (pte->swap_idx != -1) {
//                    swap_free (pte->swap_idx); // TODO swap_free
//                }
//                struct hash_elem *h = hash_cur (&i);
//                hash_delete (ptable, &pte->elem);
//                free (hash_entry (h, struct page, elem));
//                deleted = true;
//                break;
//            }
//        }
//    }
//    lock_release (&page_lock);
//    return true;
//}
//
//struct page* find_page_by_vaddr(struct hash* ptable,void* vaddr){
//    struct page* p = (struct page*)malloc(sizeof(struct page));
//    p->vaddr = pg_round_down(vaddr);
//    struct hash_elem* h = hash_find(ptable, &p->elem);
//    struct page* ret = NULL;
//
//    if(h != NULL) ret =  hash_entry(h, struct page, elem);
//    free(p);
//
//    return ret;
//}
//bool page_evict_frame (struct hash* ptable) {  // randomly evict
//    struct hash_iterator i;
//    struct thread *cur = thread_current();
//    struct page *pte = NULL;
//// supplemental page table에 있는 모든 pinning되어 있지 않은,
//// frame과 mapping되어 있는 entry 중 random하게 하나를 선택하여 swap_out 시키고
//// frame을 free시킨다. 코드는 다음과 같다
//    while (1) {
//        hash_first (&i, ptable);
//        while (hash_next (&i)) {
//            pte = hash_entry (hash_cur (&i), struct page, elem);
//            if (pte->pinned == false && pte->paddr != 0) {
//                if (thread_get_ticks () % 3 == 0)
//                    continue;
//                pte->swap_idx = swap_out (pte->paddr << 12);
//                pagedir_clear_page (pte->t->pagedir, (void *)(pte->vaddr << 12));
//                palloc_free_page ((void *)(pte->paddr << 12));
//                pte->paddr = 0;
//                return true;
//            }
//        }
//    }
//    PANIC ("page_evict_frame fail!");
//}
//
//void page_set_swap (struct hash* ptable,void *upage, void *kpage, uint32_t pid) {
//    struct hash_elem *e = get_hash_elem (ptable, upage, pid);
//    ASSERT (e != NULL);
//    struct page *pte = hash_entry (e, struct page, elem);
//    pte->paddr = get_page_number (kpage);
//    pte->swap_idx = -1;
//}
//struct page *page_get_entry (struct hash* ptable,void *vaddr, uint32_t pid) {
//    lock_acquire (&page_lock);
//    struct hash_elem *he = get_hash_elem (ptable, vaddr, pid);
//    lock_release (&page_lock);
//    if (he != NULL)
//        return hash_entry (he, struct page, elem);
//    else
//        return NULL;
//}
//bool page_swap_in_and_pinning (struct hash* ptable,void *upage, uint32_t pid) {
//    // 인자로 전달된 virtual page number와 pid에
//    // 해당하는 page entry를 찾아서 swap in 해주고 pinning을 해준다.
//    struct page *pte = page_get_entry (ptable, upage, pid);
//    lock_acquire (&swap_lock); // TODO swap_lock
//    lock_release (&swap_lock);
//    if (pte == NULL)
//        return false;
//
//    pte->pinned = true;
//
//    if (pte->paddr != 0)
//        return true;
//
//    swap_in (upage, pte->swap_idx);
//    return true;
//}
//void page_pinning_buffers (struct hash* ptable,void *buffer_, unsigned size_) {
//    //read, write syscall 함수에서 호출된다. parameter로 전달된 buffer ~ buffer + size에 해당하는
//    // virtual address space에 대해, swap out된 virtual page는 swap in 해주고 모든
//    // virtual page에 대해 pinning을 해줘 evict의 후보가 되지 않도록 한다.
//    // 같은 thread에 의해 lock이 2번 걸리지 않게 하기 위해 반드시 필요하다. 코드는 다음과 같다.
//    uint32_t buffer = ((uint32_t) buffer_ >> 12) << 12;
//    int size = size_ + (uint32_t) buffer_ - buffer;
//    uint32_t pid = thread_tid();
//    while (size > 0) {
//        page_swap_in_and_pinning (ptable,(void*) buffer, pid);
//        buffer += PGSIZE;
//        size -= PGSIZE;
//    }
//}
//void page_unpinning_buffers (struct hash* ptable,void *buffer_, unsigned size_) {
//    uint32_t buffer = ((uint32_t) buffer_ >> 12) << 12;
//    int size = size_ + (uint32_t) buffer_ - buffer;
//    uint32_t pid = thread_tid();
//    while (size > 0) {
//        struct page *pte = page_get_entry (ptable, buffer, pid);
//        ASSERT (pte != NULL);
//        pte->pinned = false;
//        buffer += PGSIZE;
//        size -= PGSIZE;
//    }
//}
//int page_swap_in_all (struct hash* ptable) {
//    struct thread *cur = thread_current();
//    struct hash_iterator i;
//    void *p;
//    int cnt = 0;
//    int res  = 0;
//    hash_first (&i, ptable);
//    while (hash_next (&i)) {
//        struct page *pte = hash_entry (hash_cur (&i), struct page, elem);
//        if (pte->paddr == 0) {
//            is_swapped[pte->swap_idx] = true; // TODO is_swapped
//        }
//
//    }
//    return res;
//}
//uint32_t page_get_idx (struct hash* ptable, const struct page *pte) {
//    uint32_t idx = (uint32_t)(pte->vaddr);
//    idx = idx << 12;
//    idx += pte->pid;
//    ASSERT (pte->pid < 0x1000);
//    return idx;
//}
