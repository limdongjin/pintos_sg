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

static void syscall_handler (struct intr_frame *);
static bool is_valid_user_ptr(const void *user_ptr);
static bool get_argv_and_verify(void* esp, void* argv[SYSCALL_MAX_ARGC]);
static int unsupported_func(void);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static bool
is_valid_user_ptr(const void *user_ptr){
    if(!user_ptr || !is_user_vaddr(user_ptr) ||
        !pagedir_get_page(thread_current()->pagedir, user_ptr))
        return false;

    return true;
}

// get argv. and verify
// if not valid, exit.
static bool
get_argv_and_verify(void* esp, void* argv[SYSCALL_MAX_ARGC]){
    ASSERT(argv != NULL);
    int num_of_syscall = *(int *)esp;

    #define ARGV0_SET_UP() { argv[0] = (void*)((int*)esp+1); }
    #define ARGV1_SET_UP() { argv[1] = (void*)((int*)esp+2); }
    #define ARGV2_SET_UP() { argv[2] = (void*)((int*)esp+3); }

    if(num_of_syscall == SYS_HALT) return true;

    ARGV0_SET_UP();
    switch (num_of_syscall) {
        // case SYS_HALT:
        //    break;
        case SYS_EXIT:
            break;
        case SYS_EXEC:
            break;
        case SYS_WAIT:
            break;
        case SYS_CREATE:
            ARGV1_SET_UP();
            break;
        case SYS_REMOVE:
            break;
        case SYS_OPEN:
            break;
        case SYS_FILESIZE:
            break;
        case SYS_READ:
            ARGV1_SET_UP();
            ARGV2_SET_UP();
            break;
        case SYS_WRITE:
            ARGV1_SET_UP();
            ARGV2_SET_UP();
            break;
        case SYS_SEEK:
            ARGV1_SET_UP();
            break;
        case SYS_TELL:
            break;
        case SYS_CLOSE:
            break;
        default:
            break;
    }

    if(argv[0] != NULL && !is_valid_user_ptr(argv[0])) return false;
    if(argv[1] != NULL &&  !is_valid_user_ptr(argv[1])) return false;
    if(argv[2] != NULL && !is_valid_user_ptr(argv[2])) return false;

    return true;
}

static int
unsupported_func(void){
    ASSERT(0);
    return -1; // not reached. but for compile.
}

void 
abnormal_exit(void) {
    exit(ABNORMAL_EXIT_CODE);
}

// get_argv -> verify -> syscall
static void
syscall_handler (struct intr_frame *f UNUSED)
{
  // SG_PRJ1 TODO_DONE
  void* syscall_argv[SYSCALL_MAX_ARGC] = {NULL, };
  bool is_success;
  is_success = get_argv_and_verify(f->esp, syscall_argv);
  
  if(!is_success){
    f->eax = ABNORMAL_EXIT_CODE;
    abnormal_exit();
    return;
  }

  switch (*(uint32_t*)(f->esp)) {
      case SYS_HALT:
          halt();
      case SYS_EXIT:
	      exit(*(int *)syscall_argv[0]);
      case SYS_EXEC:
	      f->eax = exec(*(char**)syscall_argv[0]);
          break;
      case SYS_WAIT:
	      f->eax = wait(*(int*)syscall_argv[0]);
          break;
      case SYS_CREATE:
	      f->eax = create(*(char **)syscall_argv[0],
			  *(unsigned *)syscall_argv[1]);
          break;
      case SYS_REMOVE:
	      remove(*(char**)syscall_argv[0]);
          break;
      case SYS_OPEN:
	      open(*(char**)syscall_argv[0]);
          break;
      case SYS_FILESIZE:
	      filesize(*(int*)syscall_argv[0]);
          break;
      case SYS_READ:
	      read(*(int*)syscall_argv[0],
	       *(void**)syscall_argv[1],
	       *(unsigned*)syscall_argv[2]);
          break;
      case SYS_WRITE:
          f->eax = write(*(int*)syscall_argv[0],
                         *(const void**)syscall_argv[1],
                *(unsigned*)syscall_argv[2]);
          break;
      case SYS_SEEK:
	      seek(*(int*)syscall_argv[0],
	       *(unsigned*)syscall_argv[1]);
          break;
      case SYS_TELL:
	      f->eax = tell(*(int*)syscall_argv[0]);
          break;
      case SYS_CLOSE:
	      close(*(int*)syscall_argv[0]);
          break;
      case SYS_MMAP:
	      f->eax = mmap(*(int*)syscall_argv[0],
			   *(void**)syscall_argv[1]);
          break;
      case SYS_MUNMAP:
	      munmap(*(int*)syscall_argv[0]);
          break;
      case SYS_CHDIR:
	      f->eax = chdir(*(char**)syscall_argv[0]);
          break;
      case SYS_MKDIR:
	      f->eax = mkdir(*(char**)syscall_argv[0]);
          break;
      case SYS_READDIR:
	      f->eax = readdir(*(int*)syscall_argv[0],
			  *(char**)syscall_argv[1]);
          break;
      case SYS_ISDIR:
	      f->eax = isdir(*(int*)syscall_argv[0]);
          break;
      case SYS_INUMBER:
	      f->eax = inumber(*(int*)syscall_argv[0]);
          break;
      // SG_PRJ1 TODO: register additional two syscall to handler
  }
  // thread_exit ();
}

// SG_PRJ1 TODO_DONE: Define General System Calls Implementation
void
halt (void)
{
    shutdown_power_off ();
}

void
exit (int status) {
    // TODO exit() synchronization..?
    struct thread *t = thread_current();
    t->exit_code = status;
    printf("%s: exit(%d)\n", t->name, status);

    thread_exit();
}

int
write (int fd, const void *buffer, unsigned size) {
    if(fd == 1){ // console
      putbuf((char*)buffer, size);
      return size;
    }
   return ABNORMAL_EXIT_CODE;
}

pid_t exec (const char *cmd_line){
    // is_valid_string
    char *file_name = (char*)malloc(sizeof(char)*(strlen(cmd_line)+1));
    char *tmp;
    struct file* file_obj;

    strlcpy(file_name, cmd_line, strlen(cmd_line)+1);
    file_name = strtok_r(file_name, " ", &tmp);
    file_obj = filesys_open(file_name);
    free(file_name);

    if(!file_obj){
      return ABNORMAL_EXIT_CODE;
    }
     file_close(file_obj);

    return process_execute(cmd_line);
}

int wait (pid_t pid){
  return process_wait(pid);
}

bool create (const char *file, unsigned initial_size){
  if(strlen(file) == 0) return false;
  return filesys_create(file, initial_size);
}

bool remove (const char *file){
  return filesys_remove(file);
}

int open (const char *file UNUSED){
  return unsupported_func();
}

int filesize (int fd UNUSED){
  return unsupported_func();
}

int read (int fd, void *buffer, unsigned size){
  uint8_t* console_buf;
  unsigned i;
  
  if(fd == 0){ // console
    console_buf = (uint8_t*)buffer;
    for(i=0; i<size; i++) console_buf[i] = input_getc();
    return size;  
  }

  return unsupported_func();
}

void seek (int fd UNUSED, unsigned position UNUSED){
  unsupported_func();
}
unsigned tell (int fd UNUSED){
  return unsupported_func();
}

void close (int fd UNUSED){
  unsupported_func();
}

/* Project 3 and optionally project 4. */
mapid_t mmap (int fd UNUSED, void *addr UNUSED){
  return unsupported_func();
}
void munmap (mapid_t t UNUSED){
  unsupported_func();
}

/* Project 4 only. */
bool chdir (const char *dir UNUSED){
  return unsupported_func();
}

bool mkdir (const char *dir UNUSED){
  return unsupported_func();
}

bool readdir (int fd UNUSED, char name[READDIR_MAX_LEN + 1] UNUSED){
  return unsupported_func();
}

bool isdir (int fd UNUSED){
  return unsupported_func();
}

int inumber (int fd UNUSED){
  return unsupported_func();
}

// SG_PRJ1 TODO: Define fibonacci() and max_of_four_int() system calls
// What really these system calls do would be written here.
// ... fibonacci( ... ) { ... }
// ... max_of_four_int( ... ) { ... }
//
