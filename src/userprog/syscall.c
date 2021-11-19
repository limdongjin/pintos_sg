#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <stdlib.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"
// #include "lib/user/syscall.h"
struct file
{
    struct inode *inode;        /* File's inode. */
    off_t pos;                  /* Current position. */
    bool deny_write;            /* Has file_deny_write() been called? */
};
//static void syscall_handler(struct intr_frame *);

//static bool check_user_ptr(const void *user_ptr);

//static bool get_arg_and_verify(void *esp, void *arg[SYSCALL_MAX_ARGC]);

static int unsupported_func(void);

void check_user(const uint8_t *addr);
static int get_user(const uint8_t *addr);
//static bool put_user(uint8_t *udst,uint8_t byte);
static int read_user(void *src, void *dst, size_t bytes);
static void syscall_handler (struct intr_frame *);
static struct file_desc* find_file_desc(struct thread *t,int fd);
static void is_invalid(void);

#ifdef VM
static struct mmap_desc* find_mmap_desc(struct thread *, mmapid_t fd);
#endif

void
syscall_init(void) {
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
    lock_init(&file_lock);
}

//static bool
//check_user_ptr(const void *user_ptr) {
//    if(!is_user_vaddr(user_ptr) ||
  //     !user_ptr ||
    //   !pagedir_get_page(thread_current()->pagedir, user_ptr))
   // {
    //    exit(-1);
   // }

   // return true;
//}
/*
static bool
get_arg_and_verify(void *esp, void *arg[SYSCALL_MAX_ARGC]) {
// scope : get_arg_and_verify(...){ ... }
#define SAVE_ARG_AND_VERIFY(IDX)                       \
   ({                                                  \
    check_user_ptr((void*)((int*)esp+(IDX)+1)); \
	arg[IDX] = (void*)((int*)esp+(IDX)+1);                \
    })

    ASSERT(arg != NULL);
    if (*(uint32_t*)esp == SYS_HALT) return true;

    SAVE_ARG_AND_VERIFY(0);
    switch (*(uint32_t*)esp) {
        // case SYS_HALT:
        //    break;
        case SYS_EXIT:
            break;
        case SYS_EXEC:
            break;
        case SYS_WAIT:
            break;
        case SYS_CREATE:
            SAVE_ARG_AND_VERIFY(1);
            break;
        case SYS_REMOVE:
            break;
        case SYS_OPEN:
            break;
        case SYS_FILESIZE:
            break;
        case SYS_READ:
            SAVE_ARG_AND_VERIFY(1);
            SAVE_ARG_AND_VERIFY(2);
            break;
        case SYS_WRITE:
            SAVE_ARG_AND_VERIFY(1);
            SAVE_ARG_AND_VERIFY(2);
            break;
        case SYS_SEEK:
            SAVE_ARG_AND_VERIFY(1);
            break;
        case SYS_TELL:
            break;
        case SYS_CLOSE:
            break;
        case SYS_FIBONACCI:
            break;
        case SYS_MAX_OF_FOUR_INT:
            SAVE_ARG_AND_VERIFY(1);
            SAVE_ARG_AND_VERIFY(2);
            SAVE_ARG_AND_VERIFY(3);
            break;
        default:
            printf("unsupported syscall\n");
            return false;
    }
#undef SAVE_ARG_AND_VERIFY

    return true;
}
*/
/*
static void
syscall_handler(struct intr_frame *f UNUSED) {
    void *syscall_arg[SYSCALL_MAX_ARGC] = {NULL,};
    bool is_success;

// scope: syscall_handler(...) { ... }
#define INT_ARG(IDX) (*(int*)syscall_arg[IDX])
#define CHAR_PTR_ARG(IDX) (*(char**)syscall_arg[IDX])
#define VOID_PTR_ARG(IDX) (*(void**)syscall_arg[IDX])
#define UNSIGNED_ARG(IDX) (*(unsigned*)syscall_arg[IDX])
    is_success = get_arg_and_verify(f->esp, syscall_arg);

    if (!is_success) {
        f->eax = ABNORMAL_EXIT_CODE;
        abnormal_exit();
        return;
    }

    switch (*(uint32_t *) (f->esp)) {
        case SYS_HALT:
            halt();
        case SYS_EXIT:
            exit(INT_ARG(0));
        case SYS_EXEC:
            f->eax = exec(CHAR_PTR_ARG(0));
            break;
        case SYS_WAIT:
            f->eax = wait(INT_ARG(0));
            break;
        case SYS_CREATE:
            f->eax = create(CHAR_PTR_ARG(0),
                            UNSIGNED_ARG(1));
            break;
        case SYS_REMOVE:
            f->eax = remove(CHAR_PTR_ARG(0));
            break;
        case SYS_OPEN:
            check_user_ptr(CHAR_PTR_ARG(0));
            f->eax = open(CHAR_PTR_ARG(0));
            break;
        case SYS_FILESIZE:
            f->eax = filesize(INT_ARG(0));
            break;
        case SYS_READ:
            f->eax = read(INT_ARG(0),
                 VOID_PTR_ARG(1),
                 UNSIGNED_ARG(2));
            break;
        case SYS_WRITE:
             check_user_ptr(VOID_PTR_ARG(1));
            f->eax = write(INT_ARG(0),
                           VOID_PTR_ARG(1),
                           UNSIGNED_ARG(2));
            break;
        case SYS_SEEK:
            seek(INT_ARG(0),
                 UNSIGNED_ARG(1));
            break;
        case SYS_TELL:
            f->eax = tell(INT_ARG(0));
            break;
        case SYS_CLOSE:
            close(INT_ARG(0));
            break;
        case SYS_MMAP:
            f->eax = mmap(INT_ARG(0),
                          VOID_PTR_ARG(1));
            break;
        case SYS_MUNMAP:
            munmap(INT_ARG(0));
            break;
        case SYS_CHDIR:
            f->eax = chdir(CHAR_PTR_ARG(0));
            break;
        case SYS_MKDIR:
            f->eax = mkdir(CHAR_PTR_ARG(0));
            break;
        case SYS_READDIR:
            f->eax = readdir(INT_ARG(0),
                             CHAR_PTR_ARG(1));
            break;
        case SYS_ISDIR:
            f->eax = isdir(INT_ARG(0));
            break;
        case SYS_INUMBER:
            f->eax = inumber(INT_ARG(0));
            break;
        case SYS_FIBONACCI:
            f->eax = fibonacci(INT_ARG(0));
            break;
        case SYS_MAX_OF_FOUR_INT:
            f->eax = max_of_four_int(INT_ARG(0), INT_ARG(1), INT_ARG(2), INT_ARG(3));
            break;
        default:
            printf("unsupported syscall\n");
            abnormal_exit();
    }
    // thread_exit ();
#undef INT_ARG
#undef CHAR_PTR_ARG
#undef VOID_PTR_ARG
#undef UNSIGNED_ARG

}

*/
static void
syscall_handler (struct intr_frame *f)
{
  //hex_dump(0xbfffffe0,f->esp,100,1);
  int syscall_number;
  read_user(f->esp,&syscall_number,sizeof(syscall_number));
  ASSERT(sizeof(syscall_number == 4));
  //printf("system call number = %d\n",syscall_number);

  //Store the esp, which is needed in the page fault handler.
  thread_current()->current_esp = f->esp;

  switch(syscall_number){
    case SYS_HALT: //0
    {
      halt();
      break;
    }

    case SYS_EXIT: //1
    {
      int exit_code;
      read_user(f->esp + 4,&exit_code,sizeof(exit_code));
      exit(exit_code);
      break;
    }

    case SYS_EXEC: //2
    {
      void *cmd_line;
      read_user(f->esp+4,&cmd_line,sizeof(cmd_line));
      int return_code = exec((const char*)cmd_line);
      f->eax = (uint32_t) return_code;
      break;
    }

    case SYS_WAIT: //3
    {
      pid_t pid;
      read_user(f->esp + 4,&pid,sizeof(pid));
      int ret = wait(pid);
      f->eax = (uint32_t)ret;
      break;
    }

    case SYS_CREATE: //4
    {
      const char *file_name;
      unsigned initial_size;
      read_user(f->esp + 4,&file_name,sizeof(file_name));
      read_user(f->esp + 8,&initial_size,sizeof(initial_size));
       bool return_code = create(file_name,initial_size);
      f->eax = return_code;
      break;
    }

    case SYS_REMOVE: //5
    {
      const char *file_name;
      bool return_code;
      read_user(f->esp + 4,&file_name,sizeof(file_name));
      return_code = remove(file_name);
      f->eax = return_code;
      break;
    }

    case SYS_OPEN: //6
    {
      const char *file_name;
      int return_code;
      read_user(f->esp + 4,&file_name,sizeof(file_name));
      return_code = open(file_name);
      f->eax = return_code;
      break;
    }

    case SYS_FILESIZE: //7
    {
      int fd;
      read_user(f->esp+4,&fd,sizeof(fd));
      int return_code = filesize(fd);
      f->eax = return_code;
      break;
    }

    case SYS_READ: //8
    {
      int fd;
      void *buffer;
      unsigned size;

      read_user(f->esp + 4, &fd, sizeof(fd));
      read_user(f->esp + 8, &buffer, sizeof(buffer));
      read_user(f->esp + 12, &size, sizeof(size));

      int return_code = read(fd,buffer,size);
      f->eax = (uint32_t) return_code;
      break;
    }

    case SYS_WRITE: //9
    {
      int fd;
      void *buffer;
      unsigned size;

      read_user(f->esp + 4, &fd, sizeof(fd));
      read_user(f->esp + 8, &buffer, sizeof(buffer));
      read_user(f->esp + 12, &size, sizeof(size));

      int return_code = write(fd,buffer,size);
      f->eax = (uint32_t) return_code;
      break;
    }


    case SYS_SEEK: //10
    {
      int fd;
      unsigned position;

      read_user(f->esp+4, &fd, sizeof(fd));
      read_user(f->esp+8, &position, sizeof(position));

      seek(fd,position);
      break;
    }


    case SYS_TELL://11
    {
      int fd;
      unsigned return_code;

      read_user(f->esp+4,&fd,sizeof(fd));
      return_code = tell(fd);
      f->eax = (uint32_t) return_code;
      break;
    }

    case SYS_CLOSE://12
    {
      int fd;
      read_user(f->esp+4, &fd, sizeof(fd));
      close(fd);
      break;
    }

    #ifdef VM
    case SYS_MMAP:// 13
    {
      int fd;
      void *addr;
      read_user(f->esp + 4, &fd, sizeof(fd));
      read_user(f->esp + 8, &addr, sizeof(addr));

      mmapid_t return_code = sys_mmap (fd, addr);
      f->eax = return_code;
      break;
    }

  case SYS_MUNMAP:// 14
    {
      mmapid_t mid;
      read_user(f->esp + 4, &mid, sizeof(mid));

      sys_munmap(mid);
      break;
    }
#endif
  }
}

static int
unsupported_func(void) {
    ASSERT(0);
    return -1; // not reached. but for compile.
}

void
abnormal_exit(void) {
    exit(ABNORMAL_EXIT_CODE);
}


void
halt(void) {
    shutdown_power_off();
}

void
exit(int status) {
    int i;
    struct list_elem* e = NULL;

    thread_current()->exit_code = status;
    printf("%s: exit(%d)\n", thread_current()->name, status);

    i = 3;
    while(i < 128 && thread_current()->fd_table[i] != NULL) close(i++);

    for(e = list_begin(&thread_current()->child_list);
        e != list_end(&thread_current()->child_list);
        e = list_next(e))
    {
        process_wait(list_entry(e, struct thread, i_elem)->tid);
    }

    thread_exit();
}

int
write(int fd, const void *buffer, unsigned size) {
    if(fd == 0 || fd == 2) abnormal_exit();
    struct file* cfp;
  check_user((const uint8_t*)buffer);
  check_user((const uint8_t*)buffer + size -1);
  ///   check_user_ptr(buffer);
    int ret;
    bool success = true;

    lock_acquire(&file_lock);

    if (fd == 1) { // console
        putbuf((char *) buffer, size);
        ret = size;
        goto write_done;
    }

    if(thread_current()->fd_table[fd] == NULL){
        success = false;
        goto write_done;
    }

     cfp = thread_current()->fd_table[fd];
     if(cfp->deny_write) file_deny_write(cfp);
     // ret = file_write(cfp, buffer, size);
#ifdef VM
      preload_and_pin_pages(buffer, size);
#endif
      ret = file_write(cfp, buffer,size);
#ifdef VM
      unpin_preloaded_pages(buffer, size);
#endif
 write_done:
     lock_release(&file_lock);
     if(!success) exit(-1);

     return ret;
}

pid_t
exec(const char *cmd_line) {
	  check_user((const uint8_t *)cmd_line);
    char file_name[130];
    struct file *fp;
    int i = 0;
    pid_t pid;
    while(cmd_line[i] != ' ' && (file_name[i] = cmd_line[i]) != '\0') i++;
    file_name[i] = '\0';

	    lock_acquire(&file_lock);
    fp = filesys_open(file_name);
             lock_release(&file_lock);
    if (fp == NULL) return ABNORMAL_EXIT_CODE;
     lock_acquire(&file_lock);
    file_close(fp);
         lock_release(&file_lock);
  lock_acquire(&file_lock);   // >>
  pid = process_execute(cmd_line);
  lock_release(&file_lock);
  return pid;

}

int
wait(pid_t pid) {
    return process_wait(pid);
}

bool
create(const char *file, unsigned initial_size) {
    if(file == NULL) exit(-1);
    // check_user_ptr(file);
     check_user((const uint8_t*)file);
  lock_acquire(&file_lock);
  bool success = filesys_create(file,initial_size);
  lock_release(&file_lock);
  return success;
    // return filesys_create(file, initial_size);
}

bool
remove(const char *file) {
     if(file == NULL) exit(-1);
 check_user((const uint8_t*)file);
  lock_acquire(&file_lock);
  bool success = filesys_remove(file);
  lock_release(&file_lock);
  return success;
    //return filesys_remove(file);
}

int
open(const char *file UNUSED) {
    if(file == NULL) exit(-1);
      check_user((const uint8_t*)file);
    int i, ret = -1;

    lock_acquire(&file_lock);
    struct file* fp = filesys_open(file);
    if(fp == NULL) goto open_done;

    i = 3;
    while(i < 128 && thread_current()->fd_table[i] != NULL) i++;
    if(i < 128){
        if(strcmp(thread_name(), file) == 0) file_deny_write(fp);
        thread_current()->fd_table[i] = fp;
        ret = i;
    }
 open_done:
    lock_release(&file_lock);

    return ret;
}

int
filesize(int fd UNUSED) {
    if(thread_current()->fd_table[fd] == NULL) exit(-1);
    return (int)file_length(thread_current()->fd_table[fd]);
}

int
read(int fd, void *buffer, unsigned size) {
    unsigned i = 0;
    bool success = true;
    // check_user_ptr(buffer);
    if(fd == 1 || fd == 2) {
        abnormal_exit();
    }
 check_user((const uint8_t *)buffer);
  check_user((const uint8_t *)buffer + size -1);
    lock_acquire(&file_lock);
    if (fd == 0) { // console
        while(i < size && input_getc() != '\0' && i++);
        goto read_done;
    }

    if(thread_current()->fd_table[fd] == NULL){
        success = false;
        goto read_done;
    }
#ifdef VM
      preload_and_pin_pages(buffer, size);
#endif
      i = file_read(thread_current()->fd_table[fd],buffer,size);
#ifdef VM
      unpin_preloaded_pages(buffer, size);
#endif
    // i = file_read(thread_current()->fd_table[fd], buffer, size);
 read_done:
    lock_release(&file_lock);
    if(!success) exit(-1);
    return (int)i;
}

void
seek(int fd UNUSED, unsigned position UNUSED) {
//    if(thread_current()->fd_table[fd] == NULL) abnormal_exit();
  //  file_seek(thread_current()->fd_table[fd], position);
      lock_acquire(&file_lock);
//  struct file_desc* desc = find_file_desc(thread_current(),fd);
  if(thread_current()->fd_table[fd] != NULL){
    file_seek(thread_current()->fd_table[fd], position);
  }
  else
    return;
  lock_release(&file_lock);
}

unsigned
tell(int fd UNUSED) {
   // if(thread_current()->fd_table[fd] == NULL) abnormal_exit();
   // return (unsigned )file_tell(thread_current()->fd_table[fd]);
    lock_acquire(&file_lock);
//   struct file_desc* desc = find_file_desc(thread_current(),fd);
  unsigned ret;
  if(thread_current()->fd_table[fd] != NULL){
    ret = file_tell(thread_current()->fd_table[fd]);
  }
  else
    ret = -1;
  lock_release(&file_lock);
  return ret;
}

void
close(int fd UNUSED) {
	  lock_acquire(&file_lock);
    struct file* fp = thread_current()->fd_table[fd];
    //if(fp == NULL) abnormal_exit();
    if(fp!=NULL){
      file_close(fp);
      thread_current()->fd_table[fd] = NULL;
    }
    lock_release(&file_lock);
}

/* Project 3 and optionally project 4. */
mapid_t
sys_mmap(int fd UNUSED, void *upage UNUSED) {
struct file *f = NULL;
  if (upage == NULL || pg_ofs(upage) != 0)
    return -1;
  if (fd <= 1)
    return -1;
  struct thread *cur = thread_current();

  lock_acquire (&file_lock);

  /* 1. Open file */
  // struct file_desc* desc = find_file_desc(thread_current(), fd);
  if(cur->fd_table[fd] != NULL) {
    // reopen file so that it doesn't interfere with process itself
    // it will be store in the mmap_desc struct (later closed on munmap)
    f = file_reopen (cur->fd_table[fd]);
  }
  if(f == NULL)
    goto MMAP_FAIL;
size_t file_size = file_length(f);
  if(file_size == 0)
    goto MMAP_FAIL;

  /* 2. Mapping memory pages
   First, ensure that all the page address is NON-EXIESENT. */
  size_t offset;
  for (offset = 0; offset < file_size; offset += PGSIZE) {
    void *addr = upage + offset;
    if (vm_supt_has_entry(cur->supt, addr)) goto MMAP_FAIL;
  }

  /* Now, map each page to filesystem */
  for (offset = 0; offset < file_size; offset += PGSIZE) {
    void *addr = upage + offset;

    size_t read_bytes = (offset + PGSIZE < file_size ? PGSIZE : file_size - offset);
    size_t zero_bytes = PGSIZE - read_bytes;

    vm_supt_install_filesys(cur->supt, addr,
        f, offset, read_bytes, zero_bytes, true);
  }

  /* 3. Assign mmapid */
  mmapid_t mid;
  if (! list_empty(&cur->mmap_list)) {
    mid = list_entry(list_back(&cur->mmap_list), struct mmap_desc, elem)->id + 1;
  }
  else mid = 1;

  struct mmap_desc *mmap_d = (struct mmap_desc*) malloc(sizeof(struct mmap_desc));
  mmap_d->id = mid;
  mmap_d->file = f;
  mmap_d->addr = upage;
  mmap_d->size = file_size;

  list_push_back (&cur->mmap_list, &mmap_d->elem);

  lock_release (&file_lock);
  return mid;

MMAP_FAIL:
  lock_release (&file_lock);
  return -1;
}

bool sys_munmap(mmapid_t mid)
{
  struct thread *curr = thread_current();
  struct mmap_desc *mmap_d = find_mmap_desc(curr, mid);

  if(mmap_d == NULL) { // not found such mid
    return false; // or fail_invalid_access() ?
  }

  lock_acquire (&file_lock);
  {
    // Iterate through each page
    size_t offset, file_size = mmap_d->size;
    for(offset = 0; offset < file_size; offset += PGSIZE) {
      void *addr = mmap_d->addr + offset;
      size_t bytes = (offset + PGSIZE < file_size ? PGSIZE : file_size - offset);
      vm_supt_mm_unmap (curr->supt, curr->pagedir, addr, mmap_d->file, offset, bytes);
    }

    // Free resources, and remove from the list
    list_remove(& mmap_d->elem);
    file_close(mmap_d->file);
    free(mmap_d);
  }
  lock_release (&file_lock);

  return true;
}

/* Project 4 only. */
bool
chdir(const char *dir UNUSED) {
    return unsupported_func();
}

bool
mkdir(const char *dir UNUSED) {
    return unsupported_func();
}

bool
readdir(int fd UNUSED, char name[READDIR_MAX_LEN + 1] UNUSED) {
    return unsupported_func();
}

bool
isdir(int fd UNUSED) {
    return unsupported_func();
}

int
inumber(int fd UNUSED) {
    return unsupported_func();
}

// SG_PRJ1 TODO_DONE: Define fibonacci() and max_of_four_int() system calls
int
fibonacci(int n) {
    int n1 = 1, n2 = 1, ret = 1, i;
    if (n == 0) return 0;
    for (i = 3; i <= n; i++) {
        ret = n1 + n2;
        n2 = n1;
        n1 = ret;
    }
    return ret;
}

int
max_of_four_int(int a, int b, int c, int d) {
    int ret = a;
    if (ret < b) ret = b;
    if (ret < c) ret = c;
    if (ret < d) ret = d;
    return ret;}

void check_user(const uint8_t *addr){
  if(get_user(addr) == -1){
    is_invalid();
  }
}

static int get_user(const uint8_t *addr){//address must be below PHYS_BASE
  if(!is_user_vaddr((void*)addr)){
  //if(!((void*)uaddr < PHYS_BASE)){
    return -1;
  }
  //printf("address : %d\n",*addr);
  int result;
  asm("movl $1f, %0; movzbl %1, %0; 1:"
      : "=&a"(result): "m"(*addr));
  return result;
}

static int read_user(void *src, void *dst, size_t bytes){
  int32_t value;
  size_t i;
  for(i=0;i < bytes;i++){
    value = get_user(src + i);
    if(value == -1)//invalide memory access
      is_invalid();

    *(char*)(dst + i) = value & 0xff;
  }
  return (int)bytes;
}


static void is_invalid(void){
  if(lock_held_by_current_thread(&file_lock))
    lock_release(&file_lock);
  exit(-1);
}


#ifdef VM
static struct mmap_desc* find_mmap_desc(struct thread *t, mmapid_t mid)
{
  ASSERT (t != NULL);

  struct list_elem *e;

  if (! list_empty(&t->mmap_list)) {
    for(e = list_begin(&t->mmap_list);
        e != list_end(&t->mmap_list); e = list_next(e))
    {
      struct mmap_desc *desc = list_entry(e, struct mmap_desc, elem);
      if(desc->id == mid) {
        return desc;
      }
    }
  }

  return NULL; // not found
}
#endif
