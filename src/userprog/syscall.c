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
static void syscall_handler(struct intr_frame *);

static bool is_valid_user_ptr(const void *user_ptr);

static bool get_arg_and_verify(void *esp, void *arg[SYSCALL_MAX_ARGC]);

static int unsupported_func(void);

void
syscall_init(void) {
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
    lock_init(&file_lock);
}

static inline void
check_user_string_l (const char *str, unsigned size, void *esp)
{
    while (size--)
        if(!is_valid_user_ptr((void *) (str++))) exit(-1);
}

static bool
is_valid_user_ptr(const void *user_ptr) {
    if (!user_ptr || !is_user_vaddr(user_ptr) ||
        !pagedir_get_page(thread_current()->pagedir, user_ptr))
        return false;

    return true;
}

// get arg. and verify
// if not valid, exit.
static bool
get_arg_and_verify(void *esp, void *arg[SYSCALL_MAX_ARGC]) {
// scope : get_arg_and_verify(...){ ... }
#define SAVE_ARG_AND_VERIFY(IDX)                       \
   ({                                                  \
    if(!is_valid_user_ptr((void*)((int*)esp+(IDX)+1))) return false;                                                   \
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
    // if (arg[1] != NULL && !is_valid_user_ptr(arg[1])) return false;
    // if (arg[2] != NULL && !is_valid_user_ptr(arg[2])) return false;
    // if (arg[3] != NULL && !is_valid_user_ptr(arg[3])) return false;

    return true;
}

// SG_PRJ1 TODO_DONE
// get_argv -> verify -> syscall
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
            f->eax = open(CHAR_PTR_ARG(0));
            break;
        case SYS_FILESIZE:
            filesize(INT_ARG(0));
            break;
        case SYS_READ:
            // check_user_string_l ((const char *) syscall_arg[1], (unsigned) syscall_arg[2], f->esp);
            f->eax = read(INT_ARG(0),
                 VOID_PTR_ARG(1),
                 UNSIGNED_ARG(2));
            break;
        case SYS_WRITE:
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
            // SG_PRJ1 TODO_DONE: register additional two syscall to handler
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
    //printf("abnormal\n");
    exit(ABNORMAL_EXIT_CODE);
}


// SG_PRJ1 TODO_DONE: Define General System Calls Implementation
void
halt(void) {
    //printf("halt\n");
    shutdown_power_off();
}

void
exit(int status) {
    //printf("exit\n");
    struct thread *t = thread_current();
    t->exit_code = status;
    printf("%s: exit(%d)\n", t->name, status);

    int i;

    for(i=3;i<128;i++) {
        if(thread_current()->fd[i] == NULL) continue;
        close(i);
    }

    struct thread* tt = NULL;
    struct list_elem* elem = NULL;
    for(elem = list_begin(&thread_current()->child_list);
        elem != list_end(&thread_current()->child_list);
        elem = list_next(elem)
    ){

        tt = list_entry(elem, struct thread, i_elem);
        process_wait(tt->tid);
    }

    thread_exit();
}

int
write(int fd, const void *buffer, unsigned size) {
    if(fd == 0 || fd == 2) abnormal_exit();
     //printf("write\n");
    struct file* cfp;

     if(!is_valid_user_ptr(buffer)) exit(-1);
    int ret = -1;

    lock_acquire(&file_lock);

     if (fd == 1) { // console
        putbuf((char *) buffer, size);
        ret = size;
        lock_release(&file_lock);
        return ret;
    }

     if(thread_current()->fd[fd]==NULL){
         lock_release(&file_lock);
         exit(-1);
     }
     struct thread* cur = thread_current();
     cfp = cur->fd[fd];
     if(cfp->deny_write){
         file_deny_write(cfp);
     }
     ret = file_write(cfp, buffer, size);

    lock_release(&file_lock);
     return ret;
}

pid_t
exec(const char *cmd_line) {
    ///printf("exec\n");
    char *file_name = (char *) malloc(sizeof(char) * (strlen(cmd_line) + 1));
    // char file_name[130];
    char *tmp;
    struct file *file_obj;
    //memcpy(file_name, cmd_line, strlen(cmd_line)+1);
    strlcpy(file_name, cmd_line, strlen(cmd_line) + 1);

    file_name = strtok_r(file_name, " ", &tmp);
    file_obj = filesys_open(file_name);
    free(file_name);

    if (file_obj == NULL) {
        //printf("exec : fileobj not exist\n");
        return ABNORMAL_EXIT_CODE;
        //abnormal_exit();
    }

    // file_close(file_obj);

    return process_execute(cmd_line);
}

int wait(pid_t pid) {
    return process_wait(pid);
}

bool create(const char *file, unsigned initial_size) {
     //printf("create\n");
    if(file == NULL) exit(-1);
    if(!is_valid_user_ptr(file)) exit(-1);

    return filesys_create(file, initial_size);
}

bool remove(const char *file) {
     //printf("remove\n");
    if(file == NULL) exit(-1);
    if(!is_valid_user_ptr(file)) exit(-1);

    return filesys_remove(file);
}

int open(const char *file UNUSED) {
    if(file == NULL) {
        exit(-1);
    }
    lock_acquire(&file_lock);
    struct file* fp = filesys_open(file);
    int i, ret;
    if(fp == NULL){
        ret = -1;
    }else {
        for(i=3;i<128;i++) {
            if (thread_current()->fd[i] != NULL) continue;
            if(strcmp(thread_name(), file) == 0) file_deny_write(fp);
            thread_current()->fd[i] = fp;
            ret = i;
            break;
        }
    }
    lock_release(&file_lock);
    return ret;
}

int filesize(int fd UNUSED) {
    if(thread_current()->fd[fd] == NULL) exit(-1);
    return (int)file_length(thread_current()->fd[fd]);
}

int read(int fd, void *buffer, unsigned size) {
    int i = -1;
    if(!is_valid_user_ptr(buffer) || fd == 1 || fd == 2) {
        abnormal_exit();
    }
     lock_acquire(&file_lock);
    if (fd == 0) { // console
        for (i = 0; i < size; i++) {
            if(input_getc()=='\0')
                break;
        }
        lock_release(&file_lock);
        return i;
    }

    struct thread* cur = thread_current();
    if(thread_current()->fd[fd] == NULL){
        lock_release(&file_lock);
        exit(-1);
    }
    i = file_read(cur->fd[fd], buffer, size);
//    printf("read %d\n", i);

    lock_release(&file_lock);
    return i;
}

void seek(int fd UNUSED, unsigned position UNUSED) {
    if(thread_current()->fd[fd] == NULL) abnormal_exit();
    file_seek(thread_current()->fd[fd], position);
}

unsigned tell(int fd UNUSED) {
    if(thread_current()->fd[fd] == NULL) abnormal_exit();
    return (unsigned )file_tell(thread_current()->fd[fd]);
}

void close(int fd UNUSED) {
    struct file* fp = thread_current()->fd[fd];

    if(fp == NULL) abnormal_exit();
    //file_close(fp);
    //thread_current()->fd[fd] = NULL;
    fp = NULL;
    file_close(fp);
}

/* Project 3 and optionally project 4. */
mapid_t mmap(int fd UNUSED, void *addr UNUSED) {
    return unsupported_func();
}

void munmap(mapid_t t UNUSED) {
    unsupported_func();
}

/* Project 4 only. */
bool chdir(const char *dir UNUSED) {
    return unsupported_func();
}

bool mkdir(const char *dir UNUSED) {
    return unsupported_func();
}

bool readdir(int fd UNUSED, char name[READDIR_MAX_LEN + 1] UNUSED) {
    return unsupported_func();
}

bool isdir(int fd UNUSED) {
    return unsupported_func();
}

int inumber(int fd UNUSED) {
    return unsupported_func();
}

// SG_PRJ1 TODO_DONE: Define fibonacci() and max_of_four_int() system calls
int fibonacci(int n) {
    int n1 = 1, n2 = 1, ret = 1, i;
    if (n == 0) return 0;
    for (i = 3; i <= n; i++) {
        ret = n1 + n2;
        n2 = n1;
        n1 = ret;
    }
    return ret;
}

int max_of_four_int(int a, int b, int c, int d) {
    int ret = a;
    if (ret < b) ret = b;
    if (ret < c) ret = c;
    if (ret < d) ret = d;
    return ret;
}
