#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"

#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
// #include "userprog/syscall.h"
// PRJ4
#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"

//#ifndef DEBUG_PRINT
//#ifdef DEBUG
//#define DEBUG_PRINT(fmt, args...) printf("DEBUG: %s:%d:%s(): " fmt, __FILE__, __LINE__, __func__, ##args)
//#else
//#define DEBUG_PRINT(fmt, args...) /* Don't do anything in release builds */
//#endif
//#endif

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
static void parse_cmdline(char *cmdline, int *argc_p, char *argv[CMD_ARGC_LIMIT]);
static void push_args(int argc, char* argv[CMD_ARGC_LIMIT], void** esp);

struct lock lock_for_execute;

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
    // DEBUG_PRINT("START %d\n", file_name);
  char *fn_copy;
  tid_t tid;
  struct list_elem* e = NULL;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  /* Create a new thread to execute FILE_NAME. */
    // DEBUG_PRINT("call thread_create(...)\n", file_name);
  tid = thread_create (file_name, PRI_DEFAULT, start_process, fn_copy);
    // DEBUG_PRINT("end thread_create(...)\n");
  ///// sema_down(&thread_current()->child_execute_sema);
  if (tid == TID_ERROR)
    palloc_free_page (fn_copy);
/*
  for(e = list_begin(&thread_current()->child_list);
      e != list_end(&thread_current()->child_list);
      e = list_next(e)
  ){
      if(list_entry(e, struct thread, i_elem)->flag == 1)
          return process_wait(tid);
  }*/
    // DEBUG_PRINT("END : tid = %d\n", tid);
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;

  // DEBUG_PRINT("START %d\n", file_name);
  struct intr_frame if_;
  bool success;
  struct thread* t;
  t = thread_current();

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  t->load_succeeded = load (file_name, &if_.eip, &if_.esp);

    // 부모 프로세스에서 exec 함수 수행을 재개해도 좋습니다.
    sema_up(&t->load_sema);

  /* If load failed, quit. */
  if(!t->load_succeeded){
      palloc_free_page(file_name);
      thread_exit();
  }

  // palloc_free_page (file_name);

  // sema_up(&thread_current()->parent->child_execute_sema);
  //if (!success) {
  //    thread_current()->flag = 1;
  //    exit(-1);
 // }
  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
    palloc_free_page(file_name);

  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid UNUSED) 
{
    struct thread *child;
    int exit_status;

    // tid가 잘못되었거나 wait를 두 번 이상 반복하는 경우
    // 리스트에서 찾을 수 없고 결과적으로 -1을 반환합니다.
    if (!(child = thread_get_child(child_tid)))
        return -1;

    // 자식 프로세스가 종료되기를 기다립니다.
    sema_down (&child->wait_sema);
    // 자식 프로세스를 이 프로세스의 자식 리스트에서 제거합니다.
    list_remove (&child->child_elem);
    // 자식 프로세스의 종료 상태를 얻습니다.
    exit_status = child->exit_code;
    // 자식 프로세스를 완전히 제거해도 좋습니다.
    sema_up (&child->destroy_sema);

    return exit_status;
    /*
  struct list_elem* el;
  struct list_elem* end_el;
  struct thread* t;
  int ret;

  el = list_begin(&(thread_current()->child_list));
  end_el = list_end(&(thread_current()->child_list));

  while(el != end_el && (t = list_entry(el, struct thread, i_elem))->tid != child_tid)
    el = list_next(el);
  
  if(el == end_el || t == NULL) return -1;

  sema_down(&(t->p_sema));
  ret = t->exit_code;  
  list_remove(&(t->i_elem));
  sema_up(&(t->i_sema));
  
  return ret;*/
}

/* Free the current process's resources. */
void
process_exit (void)
{

    struct thread *cur = thread_current ();
    uint32_t *pd;

    // 이 프로세스가 사용한 파일을 정리합니다.
    for (cur->next_fd--; cur->next_fd >= 2; cur->next_fd--)
        // 이미 닫힌 경우에도 안전합니다.
        file_close (cur->fd_table[cur->next_fd]);

    int mapid;
    for (mapid = 1; mapid < cur->next_mapid; mapid++)
    {
        struct mmap_file *mmap_file = find_mmap_file (mapid);
        if (mmap_file)
            do_mummap (mmap_file);
    }

    // 파일 디스크립터 테이블을 해제합니다.
    cur->fd_table += 2;
    palloc_free_page (cur->fd_table);

    // 이 프로세스의 프로그램 파일에 대한 쓰기를 허용합니다.
    // 파일을 닫는 과정에서 쓰기 금지 해제가 이루어집니다.
    file_close (cur->run_file);

    vm_destroy (&cur->vm);

    // 작업 디렉터리를 닫습니다. NULL인 경우에도 안전합니다.
    dir_close (cur->working_dir);

    /* Destroy the current process's page directory and switch back
       to the kernel-only page directory. */
    pd = cur->pagedir;
    if (pd != NULL)
    {
        /* Correct ordering here is crucial.  We must set
           cur->pagedir to NULL before switching page directories,
           so that a timer interrupt can't switch back to the
           process page directory.  We must activate the base page
           directory before destroying the process's page
           directory, or our active page directory will be one
           that's been freed (and cleared). */
        cur->pagedir = NULL;
        pagedir_activate (NULL);
        pagedir_destroy (pd);
    }
    /*
  struct thread *cur = thread_current ();
  uint32_t *pd;

  *//* Destroy the current process's page directory and switch back
     to the kernel-only page directory. *//*
    // PRJ4
  pd = cur->pagedir;
  delete_pages_by_(cur->tid);
    //
 if (pd != NULL)
    {
      *//* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). *//*
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
  sema_up(&(cur->p_sema));
  sema_down(&(cur->i_sema));*/

}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}
// 실행 중인 프로세스의 파일 디스크립터 테이블에
// 새 파일을 추가하고 새로 할당된 파일 디스크립터 번호를 반환합니다.
// 파일 커널 자료 구조에 대한 포인터가 NULL이면 -1을 반환합니다.
int
process_add_file (struct file *f)
{
    struct thread *t;
    int fd;
    if (f == NULL)
        return -1;
    t = thread_current ();
    // 동시성 문제에 대해 안전합니다.
    fd = t->next_fd++;
    t->fd_table[fd] = f;
    return fd;
}

// 실행 중인 프로세스의
// 파일 디스크럽터 번호 fd에 해당하는 파일 커널 자료 구조를 반환합니다.
// 표준 입출력, 아직 할당되지 않았거나 이미 닫힌 경우 NULL을 반환합니다.
struct file *
process_get_file (int fd)
{
    struct thread *t = thread_current ();
    if (fd <= 1 || t->next_fd <= fd)
        return NULL;
    return t->fd_table[fd];
}

// 실행 중인 프로세스의
// 파일 디스크립터 번호 fd에 해당하는 파일을 닫습니다.
// 표준 입출력, 아직 할당되지 않았거나 이미 닫힌 경우 무시합니다.
void process_close_file (int fd)
{
    struct thread *t = thread_current ();
    if (fd <= 1 || t->next_fd <= fd)
        return;
    // file_close는 NULL을 무시합니다.
    file_close (t->fd_table[fd]);
    t->fd_table[fd] = NULL;
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);
extern struct lock file_lock;

static void
parse_cmdline(char *cmdline, int *argc_p, char *argv[CMD_ARGC_LIMIT]) {
    char* cur, *rest;
    int i = 0;

    cur = strtok_r(cmdline, " ", &rest);
    argv[i++] = cur;
    while((cur = strtok_r(NULL, " ", &rest)) != NULL)
        argv[i++] = cur;

    *argc_p = i;
}

static void
push_args(int argc, char* argv[CMD_ARGC_LIMIT], void** esp){
    ASSERT( 0 <= argc && argc < CMD_ARGC_LIMIT );
    uint32_t i, tmp;
    void* argv_addr[CMD_ARGC_LIMIT];
    void* cur_esp = *esp;

    // push argv to stack
    i = argc;
    while(i--){
        tmp = strlen(argv[i])+1;
        cur_esp -= tmp;
        memcpy(cur_esp, argv[i], tmp);
        argv_addr[i] = cur_esp;
    }

    // align
    while( (*(uint32_t*)(cur_esp)) % 4 != 0) {
        cur_esp -= sizeof(uint8_t);
        *(uint8_t *)cur_esp = 0;
    }

   // null
    memset((cur_esp -= sizeof(char*)), 0, sizeof(char*));

    // push argv_addr[i] for i
    i = argc;
    while(i--)
      memcpy((cur_esp -= sizeof(char*)), &(argv_addr[i]), sizeof(char*));
    

    // push **argv
    argv_addr[argc] = cur_esp;
    memcpy((cur_esp -= sizeof(char**)), &(argv_addr[argc]), sizeof(char**));

    // push argc
    memcpy((cur_esp -= sizeof(int)), &argc, sizeof(int));

    // push ret addr
    memset((cur_esp -= sizeof( void(*)() )), 0, sizeof( void(*)() ));

    *esp = cur_esp;
}

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp)
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;
  int cmd_argc = 0;
  
  // NOTE. cmd_argv's component is cmd_cpy's relative pointer that passed by strtok_r(..) 
  // SO, you MUST ONLY free(cmd_cpy)
  char* cmd_argv[CMD_ARGC_LIMIT]; 
  //char* cmd_cpy = NULL;
  char cmd_cpy[130];
  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  strlcpy(cmd_cpy, file_name, 130);
  parse_cmdline(cmd_cpy, &cmd_argc, cmd_argv);
  memcpy(t->name, cmd_argv[0], sizeof(t->name)/sizeof(char));

  /* Open executable file. */
    lock_acquire(&file_lock);
  file = filesys_open (cmd_argv[0]);
  if (file == NULL)
    {
      lock_release(&file_lock);
      printf ("load: %s: open failed\n", cmd_argv[0]);
      goto done; 
    }
    t->run_file = file;
    file_deny_write (file);
    lock_release (&file_lock);

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", cmd_argv[0]);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;
  
  push_args(cmd_argc, cmd_argv, esp);

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;
  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
    //lock_acquire(&file_lock);
  //file_close (file);
    //lock_release(&file_lock);

  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
    ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
    ASSERT (pg_ofs (upage) == 0);
    ASSERT (ofs % PGSIZE == 0);
    file_seek (file, ofs);
    while (read_bytes > 0 || zero_bytes > 0)
    {
        /* Calculate how to fill this page.
           We will read PAGE_READ_BYTES bytes from FILE
           and zero the final PAGE_ZERO_BYTES bytes. */
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;
        struct vm_entry *vme = (struct vm_entry *)malloc(sizeof (struct vm_entry));
        if (vme == NULL)
            return false;

        memset (vme, 0, sizeof (struct vm_entry));
        vme->type = VM_BIN;
        vme->file = file;
        vme->offset = ofs;
        vme->read_bytes = page_read_bytes;
        vme->zero_bytes = page_zero_bytes;
        vme->writable = writable;
        vme->vaddr = upage;

        insert_vme (&thread_current ()->vm, vme);

        /* Get a page of memory. */
  /*      uint8_t *kpage = palloc_get_page (PAL_USER);
        if (kpage == NULL){
            if (file_read(file,
                          cur_frame,
                          page_read_bytes) == (int) page_read_bytes) {
                memset (cur_frame + page_read_bytes, 0, page_zero_bytes);
                insert_page(upage, cur_frame, writable);
            }else PANIC ("load_segment fail");
        } else{
            *//* Load this page. *//*
            if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes){
                palloc_free_page (kpage);
                return false;
            }
            memset (kpage + page_read_bytes, 0, page_zero_bytes);

            *//* Add the page to the process's address space. *//*
            if (!install_page (upage, kpage, writable)){
                palloc_free_page (kpage);
                return false;
            }
            insert_page(upage, kpage, writable);
        }*/

        /* Advance. */
        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        upage += PGSIZE;
        ofs += page_read_bytes;
    }
    return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp)
{
    struct page *kpage;
    void *upage = ((uint8_t *) PHYS_BASE) - PGSIZE;

    struct vm_entry *vme = (struct vm_entry *)malloc(sizeof(struct vm_entry));
    if (vme == NULL)
        return false;

    kpage = alloc_page (PAL_USER | PAL_ZERO);
    if (kpage != NULL)
    {
        kpage->vme = vme;
        add_page_to_lru_list (kpage);

        if (!install_page (upage, kpage->kaddr, true))
        {
            free_page_kaddr (kpage);
            free (vme);
            return false;
        }
        *esp = PHYS_BASE;

        memset (kpage->vme, 0, sizeof (struct vm_entry));
        kpage->vme->type = VM_ANON;
        kpage->vme->vaddr = upage;
        kpage->vme->writable = true;
        kpage->vme->is_loaded = true;

        insert_vme (&thread_current ()->vm, kpage->vme);
    }
    return true;
/*    uint8_t *kpage;
    bool success = false;

    kpage = palloc_get_page (PAL_USER | PAL_ZERO);
    if (kpage != NULL){
        success = install_page(((uint8_t *)PHYS_BASE) - PGSIZE,
                               kpage,
                               true);
        if(!success){
            palloc_free_page(kpage);
            return false;
        }
        insert_page(((uint8_t *) PHYS_BASE) - PGSIZE, kpage,
                    true);
        *esp = PHYS_BASE;
        return true;
    }
    while((kpage = palloc_get_page(PAL_USER | PAL_ZERO)) == NULL)
        evict_frame();
    ASSERT (kpage != NULL);
    success = install_page (((uint8_t *)PHYS_BASE)-PGSIZE, kpage, true);
    insert_page(((uint8_t *)PHYS_BASE)-PGSIZE, kpage, true);
    *esp = PHYS_BASE;
    return success;*/

}
/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
    return (pagedir_get_page (t->pagedir, upage) == NULL
               && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
bool
handle_mm_fault (struct vm_entry *vme)
{
    struct page *kpage;
    kpage = alloc_page (PAL_USER);
    ASSERT (kpage != NULL);
    ASSERT (pg_ofs (kpage->kaddr) == 0);
    ASSERT (vme != NULL);
    kpage->vme = vme;

    switch (vme->type)
    {
        case VM_BIN:
        case VM_FILE:
            if (!load_file (kpage->kaddr, vme) ||
                !install_page (vme->vaddr, kpage->kaddr, vme->writable))
            {
                NOT_REACHED ();
                free_page_kaddr (kpage);
                return false;
            }
            vme->is_loaded = true;
            add_page_to_lru_list (kpage);
            return true;
        case VM_ANON:
            swap_in (vme->swap_slot, kpage->kaddr);
            ASSERT (pg_ofs (kpage->kaddr) == 0);
            if (!install_page (vme->vaddr, kpage->kaddr, vme->writable))
            {
                NOT_REACHED ();
                free_page_kaddr (kpage);
                return false;
            }
            vme->is_loaded = true;
            add_page_to_lru_list (kpage);
            return true;
        default:
            NOT_REACHED ();
    }
}

struct mmap_file *
find_mmap_file (int mapid)
{
    struct list_elem *e;
    for (e = list_begin (&thread_current ()->mmap_list);
         e != list_end (&thread_current ()->mmap_list);
         e = list_next (e))
    {
        struct mmap_file *f = list_entry (e, struct mmap_file, elem);
        // 같은 것을 찾았으면 바로 반환합니다.
        if (f->mapid == mapid)
            return f;
    }
    // 찾지 못했습니다.
    return NULL;
}

void
do_mummap (struct mmap_file *mmap_file)
{
    ASSERT (mmap_file != NULL);

    struct list_elem *e;
    for (e = list_begin (&mmap_file->vme_list);
         e != list_end (&mmap_file->vme_list); )
    {
        struct vm_entry *vme = list_entry (e, struct vm_entry, mmap_elem);
        if (vme->is_loaded &&
            pagedir_is_dirty(thread_current ()->pagedir, vme->vaddr))
        {
            if (file_write_at (vme->file, vme->vaddr, vme->read_bytes, vme->offset)
                != (int) vme->read_bytes)
                NOT_REACHED ();
            free_page_vaddr (vme->vaddr);
        }
        vme->is_loaded = false;
        e = list_remove (e);
        delete_vme (&thread_current()->vm, vme);
    }
    list_remove (&mmap_file->elem);
    free (mmap_file);
}

void
expand_stack (void *addr)
{
    struct page *kpage;
    void *upage = pg_round_down (addr);

    struct vm_entry *vme = (struct vm_entry *)malloc(sizeof(struct vm_entry));
    if (vme == NULL)
        return false;

    kpage = alloc_page (PAL_USER | PAL_ZERO);
    if (kpage != NULL)
    {
        kpage->vme = vme;
        add_page_to_lru_list (kpage);

        if (!install_page (upage, kpage->kaddr, true))
        {
            free_page_kaddr (kpage);
            free (vme);
            return false;
        }

        memset (kpage->vme, 0, sizeof (struct vm_entry));
        kpage->vme->type = VM_ANON;
        kpage->vme->vaddr = upage;
        kpage->vme->writable = true;
        kpage->vme->is_loaded = true;

        insert_vme (&thread_current ()->vm, kpage->vme);
    }
}