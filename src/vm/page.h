#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <stdint.h>
#include <debug.h>
#include <hash.h>
#include "threads/synch.h"

struct page_entry {
    uint32_t vpn;   // virtual page number
    uint32_t ppn;   // physical page number
    uint32_t pid;
    struct hash_elem elem;
    int32_t swap_idx;   // if page -> frame, idx = -1
    // otherwise, idx >= 0
    struct thread *t;
    bool pinned;
    bool is_on_disk;
    bool writable;
};

struct lock page_lock;
void *frame_for_swap;


void page_table_init ();
void page_insert (void *upage, void *knpage, bool writable);
bool page_delete (void *upage, uint32_t pid);
bool page_destroy_by_pid (uint32_t pid);
bool page_evict_frame ();
void page_set_all_accessd_false ();
void page_set_swap (void *upage, void *kpage, uint32_t pid);
bool page_swap_in_and_pinning (void *upage, uint32_t pid);
void page_pinning_buffers (void *buffer_, unsigned size_);
void page_unpinning_buffers (void *buffer_, unsigned size_);
int page_swap_in_all ();
uint32_t get_page_number (void *);
uint32_t page_get_idx(const struct page_entry *pte);
struct page_entry *page_get_entry (void *vaddr, uint32_t pid);
struct hash_elem *get_hash_elem (void *vaddr, uint32_t pid);

#endif

//#ifndef VM_PAGE_H
//#define VM_PAGE_H
//#include "lib/kernel/hash.h"
//#include "synch.h"
//#define VM_BIN 0
//#define VM_FILE 1
//#define VM_ANON 2
//
//struct page {
//    uint8_t type; // VM_BIN or VM_FILE or VM_ANON
//    //void* vaddr; // virtual
//    //void* paddr; // physical
//    uint32_t vaddr;
//    uint32_t paddr;
//    uint32_t pid;
//
//    struct file *file;
//    size_t offset;
//    size_t read_bytes;
//    size_t zero_bytes;
//
//    struct hash_elem elem;
//
//    size_t swap_slot; // for swapping
//    struct list_elem mmap_elem; // for memory_mapped_file
//    bool writable;
//    bool is_loaded;
//    bool in_disk; // is_on_disk
//    bool pinned;
//    struct thread* t;
//    int swap_idx; // for swapping. stores the swap idx if the page is swapped out
//    bool dirty;
//    bool status; // frame, swap, filesys,
//};
//
//struct lock page_lock;
//void* frame_for_swap;
//
//void ptable_init(struct hash *ptable);
////bool insert_page(struct hash* ptable, struct page* p);
//bool insert_page(struct hash* ptable, void* vaddr, void *paddr, bool writable);
//// bool delete_page_by_vaddr(struct  hash* ptable, void* vaddr);
//struct page* find_page_by_vaddr(struct hash *ptable,void* vaddr);
//
//// void ptable_destroy(struct hash *ptable);
//uint32_t page_get_idx(struct hash* ptable, const struct page *pte);
//uint32_t get_page_number (void *);
//
//bool page_delete_by_pid(struct hash* ptable, void* vaddr, uint32_t pid);
//bool page_destroy_by_pid (uint32_t pid);
//bool page_evict_frame (struct hash* ptable);
//
//void page_set_swap (struct hash* ptable,void *upage, void *kpage, uint32_t pid);
//struct hash_elem *get_hash_elem ( struct hash* ptable  ,void *vaddr, uint32_t pid);
//
//void page_pinning_buffers (struct hash* ptable,void *buffer_, unsigned size_);
//void page_unpinning_buffers (struct hash* ptable,void *buffer_, unsigned size_);
//struct page *page_get_entry (struct hash* ptable,void *vaddr, uint32_t pid);
//int page_swap_in_all (struct hash* ptable);
//#endif
