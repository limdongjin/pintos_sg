////
//// Created by imdongjin on 21. 11. 11..
////
//
//#include "vm/page.h"
//#include "vm/frame.h"
//#include "vm/swap.h"
//#include "threads/vaddr.h"
//#include <stdio.h>
//#include <stdlib.h>
//#include "threads/thread.h"
//#include "threads/palloc.h"
//#include "userprog/pagedir.h"
//
//void frame_init(void)
//{
//    list_init(&frame_table);
//}
//struct frame* frame_insert(void *vaddr, void *paddr, bool writable)
//{
//    // 위의 frame_insert함수를 src/vm/frame.c에 추가하였고 이 함수에서는 위와 같이 virtual address와 physical address,
//    // writable에 대한 정보를 받아 해당 mapping 정보를 frame_entry로 저장하여 frame_table에 추가하여 줄 수 있도록 하였다.
//    // 이 때 physical address가 null인 경우에는 free frame을 할당하여 주어야 하므로,
//    // free한 frame이 없는 경우에는 evict_frame()호출하여 replacement algorithm에 따라 free frame을 만들어줄 수 있도록 하고
//    // 이에 따라 virtual address와 physical address를 mapping할 수 있도록 하였다.
//    struct frame *frame=(struct frame*)malloc(sizeof(struct frame));
//    struct thread* cur=thread_current();
//    frame->vaddr=pg_round_down(vaddr);
//    frame->k_vaddr=pg_round_down(paddr);
//    frame->frame_holder_thread=cur;
//    //frame->page_entry=page;
//    if(paddr!=NULL)
//    {
//        list_push_back(&frame_table, &frame->elem);
//        return frame;
//    }
//
//    paddr=palloc_get_page(PAL_USER);
//    if(paddr==NULL)
//    {
//        evict_frame();
//        paddr=palloc_get_page(PAL_USER);
//    }
//    frame->k_vaddr=pg_round_down(paddr);
//    list_push_back(&frame_table, &frame->elem);
//
//    return frame;
//}
//bool frame_delete(struct frame * frame)
//{
//    list_remove(&frame->elem);
//}
//struct frame* get_frame_entry(void *paddr)
//{
//    struct list_elem *elePtr;
//    struct frame *frame;
//    for(elePtr=list_begin(&frame_table); elePtr!=list_end(&frame_table); elePtr=list_next(elePtr))
//    {
//        frame=list_entry(elePtr, struct frame, elem);
//        if(pg_round_down(paddr)==frame->k_vaddr)
//        {
//            return frame;
//        }
//    }
//    return NULL;
//}
//bool evict_frame(void)
//{
//    struct list_elem *elePtr;
//    struct frame *victim_frame;
//    elePtr=list_begin(&frame_table);
//    victim_frame=list_entry(elePtr, struct frame, elem);
//    struct thread *victim_thread=victim_frame->frame_holder_thread;
////    struct thread *page_table=&victim_thread->ptable;
//    struct page* victim_page= find_page_by_vaddr(&victim_thread->ptable, victim_frame->vaddr);
//    victim_page->paddr=NULL;
//    victim_page->swap_idx=swap_out(victim_frame->vaddr, victim_frame->k_vaddr);
//    pagedir_clear_page(victim_frame->frame_holder_thread->pagedir, victim_frame->vaddr);
//    palloc_free_page(victim_frame->k_vaddr);
//    list_remove(&victim_frame->elem);
//    free(victim_frame);
//    return true;
//
//}
