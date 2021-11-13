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
#include "vm/page.h"
// #include "lib/user/syscall.h"
struct file
{
    struct inode *inode;        /* File's inode. */
    off_t pos;                  /* Current position. */
    bool deny_write;            /* Has file_deny_write() been called? */
};
static void syscall_handler(struct intr_frame *);

static bool get_arg_and_verify(void *esp, void *arg[SYSCALL_MAX_ARGC]);

static int unsupported_func(void);

void
syscall_init(void) {
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
    lock_init(&file_lock);
}

// TODO PRJ4 check logic..
bool
check_user_ptr(const void *user_ptr, void *esp) {
    if(user_ptr==NULL){
        return false;
    }
    else{
        if(!(is_user_vaddr(user_ptr) && user_ptr>=(void*)0x08048000UL)){
            return false;
        }
        if(!get_pge(user_ptr)){
            if(!is_valid_stack((int32_t) user_ptr, (int32_t)esp))
                return false;
            stack_grow(user_ptr);
            return true;
        }
    }
//    if(!is_user_vaddr(user_ptr) ||
//       !user_ptr || user_ptr < (void*)0x08048000UL)
//    {
//        exit(-1);
//        return false;
//    }
//    if(!get_pge(user_ptr)){
//        if(!is_valid_stack((int32_t)user_ptr, (int32_t)esp))
//            return false;
//       stack_grow(user_ptr);
//        return true;
//    }
//    return true;
}

static bool
get_arg_and_verify(void *esp, void *arg[SYSCALL_MAX_ARGC]) {
// scope : get_arg_and_verify(...){ ... }
#define SAVE_ARG_AND_VERIFY(IDX)                       \
   ({                                                  \
    check_user_ptr((void*)((int*)esp+(IDX)+1), esp); \
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
    check_user_ptr((const void*)f->esp, f->esp);
    switch (*(uint32_t *) (f->esp)) {
        case SYS_HALT:
            halt();
        case SYS_EXIT:
            // check_user_ptr(INT_ARG(0), f->esp);
            exit(INT_ARG(0));
        case SYS_EXEC:
            check_user_ptr(CHAR_PTR_ARG(0), f->esp);
            f->eax = exec(CHAR_PTR_ARG(0));
            break;
        case SYS_WAIT:
            f->eax = wait(INT_ARG(0));
            break;
        case SYS_CREATE:
            check_user_ptr(CHAR_PTR_ARG(0), f->esp);
            f->eax = create(CHAR_PTR_ARG(0),
                            UNSIGNED_ARG(1));
            break;
        case SYS_REMOVE:
            check_user_ptr(CHAR_PTR_ARG(0), f->esp);
            f->eax = remove(CHAR_PTR_ARG(0));
            break;
        case SYS_OPEN:
            check_user_ptr(CHAR_PTR_ARG(0), f->esp);
            f->eax = open(CHAR_PTR_ARG(0));
            break;
        case SYS_FILESIZE:
            f->eax = filesize(INT_ARG(0));
            break;
        case SYS_READ:
            check_user_ptr(VOID_PTR_ARG(1), f->esp);
            f->eax = read(INT_ARG(0),
                 VOID_PTR_ARG(1),
                 UNSIGNED_ARG(2));
            break;
        case SYS_WRITE:
            check_user_ptr(VOID_PTR_ARG(1), f->esp);
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
    while(i < 128 && thread_current()->fd_table[i] != NULL){
	    close(i++);
    }
    if(thread_current()->exec_file != NULL){
    	file_close(thread_current()->exec_file);
    	thread_current()->exec_file = NULL;
    }
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
    if(fd < 0 || fd >= 128) exit(-1);

    struct file* cfp;

    // check_user_ptr(buffer, NULL);
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
     ret = file_write(cfp, buffer, size);

 write_done:
     lock_release(&file_lock);
     if(!success) exit(-1);

     return ret;
}

pid_t
exec(const char *cmd_line) {
    char file_name[130];
    struct file *fp;
    int i = 0;

    while(cmd_line[i] != ' ' && (file_name[i] = cmd_line[i]) != '\0') i++;
    file_name[i] = '\0';

    fp = filesys_open(file_name);

    if (fp == NULL) return ABNORMAL_EXIT_CODE;

    file_close(fp);

    return process_execute(cmd_line);
}

int
wait(pid_t pid) {
    return process_wait(pid);
}

bool
create(const char *file, unsigned initial_size) {
     if(file == NULL) exit(-1);
    // check_user_ptr(file, NULL);

    return filesys_create(file, initial_size);
}

bool
remove(const char *file) {
     if(file == NULL) exit(-1);
    // check_user_ptr(file, NULL);

    return filesys_remove(file);
}

int
open(const char *file UNUSED) {
    if(file == NULL) exit(-1);
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
    if(buffer > PHYS_BASE) exit(-1);
   // check_user_ptr(buffer, NULL);
    if(fd == 1 || fd == 2) {
        abnormal_exit();
    }
    if(fd < 0 || fd >= 128) exit(-1);

    lock_acquire(&file_lock);
    if (fd == 0) { // console
        while(i < size && input_getc() != '\0' && i++);
        goto read_done;
    }

    if(thread_current()->fd_table[fd] == NULL){
        success = false;
        goto read_done;
    }

    i = file_read(thread_current()->fd_table[fd], buffer, size);
 read_done:
    lock_release(&file_lock);
    if(!success) exit(-1);
    return (int)i;
}

void
seek(int fd UNUSED, unsigned position UNUSED) {
    if(thread_current()->fd_table[fd] == NULL) abnormal_exit();
    file_seek(thread_current()->fd_table[fd], position);
}

unsigned
tell(int fd UNUSED) {
    if(thread_current()->fd_table[fd] == NULL) abnormal_exit();
    return (unsigned )file_tell(thread_current()->fd_table[fd]);
}

void
close(int fd UNUSED) {
    struct file* fp = thread_current()->fd_table[fd];

    if(fp == NULL) abnormal_exit();
    file_close(fp);
    thread_current()->fd_table[fd] = NULL;
}

/* Project 3 and optionally project 4. */
mapid_t
mmap(int fd UNUSED, void *addr UNUSED) {
    return unsupported_func();
}

void
munmap(mapid_t t UNUSED) {
    unsupported_func();
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
    return ret;
}

bool is_valid_stack(int32_t addr, int32_t esp){
    return is_user_vaddr(addr) && esp-addr<=32 && 0xC0000000UL-addr<=8*1024*1024;
}
