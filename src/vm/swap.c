#include "swap.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/interrupt.h"
#include "vm/page.h"
#include <stdlib.h>
#define SPP (PGSIZE / BLOCK_SECTOR_SIZE)
#define SWAP_IDX_SIZE (block_size (swap_block) / SPP)
int swap_cnt = 0;
void swap_init () {
    swap_block = block_get_role (BLOCK_SWAP);
    if (swap_block == NULL)
        PANIC ("swap_block failed!");

    is_swapped = malloc (SWAP_IDX_SIZE);

    int i;
    for (i = 0; i < SWAP_IDX_SIZE; i++) {
        is_swapped[i] = false;
    }
    lock_init (&swap_lock);
    return;
}

uint32_t swap_out (void *frame) {
    ASSERT (is_kernel_vaddr (frame));
    uint32_t swap_idx;
    lock_acquire (&swap_lock);
    /* swap disk의 빈 공간을 찾는다. */
    for (swap_idx = 0; swap_idx < SWAP_IDX_SIZE; swap_idx++) {
        if (is_swapped[swap_idx] == false) {
            is_swapped[swap_idx] = true;
            break;
        }
    }
    /* 위에서 찾은 빈 공간에 frame의 내용을 write한다. */
    int i;
    for (i = 0; i < SPP; i++) {
        block_write (swap_block, swap_idx * SPP + i, frame + i * BLOCK_SECTOR_SIZE);
    }
    lock_release (&swap_lock);
    return swap_idx;
}

void swap_in (void *upage, uint32_t swap_idx) {
    ASSERT (is_user_vaddr (upage));
    void *kpage = palloc_get_page (PAL_USER);
    while (kpage == NULL) {
        page_evict_frame ();
        kpage = palloc_get_page (PAL_USER);
    }
    struct page_entry *pte = page_get_entry (upage, thread_tid());
    ASSERT (pte != NULL);
    ASSERT (kpage != NULL);
    int i;
    lock_acquire (&swap_lock);
    for (i = 0; i < SPP; i++) {
        block_read (swap_block, swap_idx * SPP + i, kpage + i * BLOCK_SECTOR_SIZE);
    }
    pagedir_set_page (thread_current()->pagedir, upage, kpage, pte->writable);
    page_set_swap (upage, kpage, thread_tid());
    is_swapped[swap_idx] = false;
    lock_release (&swap_lock);
    return;
}

void swap_free (uint32_t swap_idx) {
    lock_acquire (&swap_lock);
    is_swapped[swap_idx] = false;
    lock_release (&swap_lock);
    return;
}


//#include "swap.h"
//#include "threads/vaddr.h"
//#include "threads/synch.h"
//#include "userprog/pagedir.h"
//#include "threads/palloc.h"
//#include "threads/thread.h"
//#include "threads/interrupt.h"
//#include "vm/page.h"
//#define SPP (PGSIZE / BLOCK_SECTOR_SIZE)
//#define SWAP_IDX_SIZE (block_size (swap_block) / SPP)
//int swap_cnt = 0;
//void swap_init () {
//    swap_block = block_get_role (BLOCK_SWAP);
//    if (swap_block == NULL)
//        PANIC ("swap_block failed!");
//
//    is_swapped = malloc (SWAP_IDX_SIZE);
//
//    int i;
//    for (i = 0; i < SWAP_IDX_SIZE; i++) {
//        is_swapped[i] = false;
//    }
//    lock_init (&swap_lock);
//    return;
//}
//
//uint32_t swap_out (void *frame) {
//    // parameter로 넘겨진 frame을 disk의 연속된 빈 sector에 write한 후,
//    // write한 sector의 첫 번째 index를 return한다. 코드는 다음과 같다.
//    //is_swapped[]는 bool 배열로, swap table의 역할을 한다.
//    ASSERT (is_kernel_vaddr (frame));
//    uint32_t swap_idx;
//    lock_acquire (&swap_lock);
//    /* swap disk의 빈 공간을 찾는다. */
//    for (swap_idx = 0; swap_idx < SWAP_IDX_SIZE; swap_idx++) {
//        if (is_swapped[swap_idx] == false) {
//            is_swapped[swap_idx] = true;
//            break;
//        }
//    }
//    /* 위에서 찾은 빈 공간에 frame의 내용을 write한다. */
//    int i;
//    for (i = 0; i < SPP; i++) {
//        block_write (swap_block, swap_idx * SPP + i, frame + i * BLOCK_SECTOR_SIZE);
//    }
//    lock_release (&swap_lock);
//    return swap_idx;
//}
//
//void swap_in (void *upage, uint32_t swap_idx) {
//    // parameter로 넘겨진 swap_idx부터 PGSIZE ( = 4,096KB)만큼을 upage로 read한 후,
//    // 해당 frame을 인자로 넘어온 upage에 매핑시켜준다. 코드는 다음과 같다.
//    ASSERT (is_user_vaddr (upage));
//    void *kpage = palloc_get_page (PAL_USER);
//    while (kpage == NULL) {
//        page_evict_frame (&thread_current()->ptable);
//        kpage = palloc_get_page (PAL_USER);
//    }
//    struct page_entry *pte = page_get_entry (upage, thread_tid());
//    ASSERT (pte != NULL);
//    ASSERT (kpage != NULL);
//    int i;
//    lock_acquire (&swap_lock);
//    for (i = 0; i < SPP; i++) {
//        block_read (swap_block, swap_idx * SPP + i, kpage + i * BLOCK_SECTOR_SIZE);
//    }
//    pagedir_set_page (thread_current()->pagedir, upage, kpage, pte->writable);
//    page_set_swap (upage, kpage, thread_tid());
//    is_swapped[swap_idx] = false;
//    lock_release (&swap_lock);
//    return;
//}
//
//void swap_free (uint32_t swap_idx) {
//    lock_acquire (&swap_lock);
//    is_swapped[swap_idx] = false;
//    lock_release (&swap_lock);
//    return;
//}

//#include <stdio.h>
//#include <stdlib.h>
//#include <bitmap.h>
//#include "threads/palloc.h"
//#include "threads/thread.h"
////#include "vm/swap.h"
//#include "threads/vaddr.h"
//#include "vm/page.h"
//#include "vm/frame.h"
//#include "vm/swap.h"
//#include "userprog/pagedir.h"
//#include "devices/block.h"
//const size_t BLOCKS_PER_PAGE=PGSIZE/BLOCK_SECTOR_SIZE;//한 페이지>당 블락 수
//struct block *swap_disk;
//bool *swap_used;//swapdisk의 index위치에  현재 저장되어 있는지
//void swap_init() {
//    swap_disk = block_get_role(BLOCK_SWAP);
//    int block_num = block_size(swap_disk) / BLOCKS_PER_PAGE;//swap disk에 들어갈 수 있는 최대page수
//    if (swap_disk) {
//        swap_used = (bool * )malloc(sizeof(bool) * block_num);
//        int i;
//        for (i = 0; i < block_num; i++) {
//            swap_used[i] = false;//swap disk에 들어와있는 페이지 하>나도 없음.
//        }
//    }
//}
//void swap_in(void *upage, void *kpage, int swap_idx)
//{
//    if(swap_used[swap_idx])
//    {
//        int i;
//        int start=BLOCKS_PER_PAGE*swap_idx;
//        for(i=0; i<BLOCKS_PER_PAGE; i++)
//        {
//            block_read(swap_disk, start+i, BLOCK_SECTOR_SIZE*i+kpage);
//        }
//        swap_used[swap_idx]=false;
//        struct thread* cur=thread_current();
//        struct hash *page_table=&(cur->ptable);
//        struct page *page=find_page_by_vaddr(page_table, upage);
//
//        page->swap_idx=-1;
//        pagedir_set_page(cur->pagedir, pg_round_down(upage), pg_round_down(kpage), page->writable);
//    }
//}
//int swap_out(void *upage, void *kpage)
//{
//    int i;
//    int idx;
//    int block_num=block_size(swap_disk)/BLOCKS_PER_PAGE;
//    for(idx=0; idx<block_num; idx++)
//    {
//        if(swap_used[idx]==false)
//            break;
//    }
//    int start=BLOCKS_PER_PAGE*idx;
//    for(i=0; i<BLOCKS_PER_PAGE;i++)
//    {
//        block_write(swap_disk, start+i, BLOCK_SECTOR_SIZE*i+kpage);
//    }
//
//    swap_used[idx]=true;
//
//    return idx;
//    //  struct frame_entry* frame= get_frame_entry(void *paddr)
//}