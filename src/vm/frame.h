//#ifndef VM_FRAME_H
//#define VM_FRAME_H
//struct frame {
//    void *vaddr;
//    void *k_vaddr; // virtual address of kernel
////    struct page *p;		// 페이지 구조체
//    struct thread* frame_holder_thread;
//    struct list_elem elem;
//};
//struct list frame_table; // frame entrys list for on pyisical memory
//
//void frame_init(void);
//struct frame *frame_insert(void *vaddr, void *paddr, bool writable);
//bool frame_delete(struct frame* frame);
//struct frame* get_frame_entry(void *paddr);
//bool evict_frame(void);
//
//#endif