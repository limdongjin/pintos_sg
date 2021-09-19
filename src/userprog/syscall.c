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

static void syscall_handler(struct intr_frame *);

static bool is_valid_user_ptr(const void *user_ptr);

static bool get_arg_and_verify(void *esp, void *arg[SYSCALL_MAX_ARGC]);

static int unsupported_func(void);

void
syscall_init(void) {
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
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
// scope : get_argv_and_verify(...){ ... }
#define SAVE_ARG(IDX) { arg[IDX] = (void*)((int*)esp+(IDX)+1); }
    ASSERT(arg != NULL);
    if (*(uint32_t*)esp == SYS_HALT) return true;

    SAVE_ARG(0);
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
            SAVE_ARG(1);
            // ARGV1_SET_UP();
            break;
        case SYS_REMOVE:
            break;
        case SYS_OPEN:
            break;
        case SYS_FILESIZE:
            break;
        case SYS_READ:
            SAVE_ARG(1);
            SAVE_ARG(2);
            break;
        case SYS_WRITE:
            SAVE_ARG(1);
            SAVE_ARG(2);
            break;
        case SYS_SEEK:
            SAVE_ARG(1)
            break;
        case SYS_TELL:
            break;
        case SYS_CLOSE:
            break;
        case SYS_FIBONACCI:
            break;
        case SYS_MAX_OF_FOUR_INT:
            SAVE_ARG(1);
            SAVE_ARG(2);
            SAVE_ARG(3);
            break;
        default:
            printf("unsupported syscall\n");
            return false;
    }
#undef SAVE_ARG
    if (arg[0] != NULL && !is_valid_user_ptr(arg[0])) return false;
    if (arg[1] != NULL && !is_valid_user_ptr(arg[1])) return false;
    if (arg[2] != NULL && !is_valid_user_ptr(arg[2])) return false;
    if (arg[3] != NULL && !is_valid_user_ptr(arg[3])) return false;

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
            remove(CHAR_PTR_ARG(0));
            break;
        case SYS_OPEN:
            open(CHAR_PTR_ARG(0));
            break;
        case SYS_FILESIZE:
            filesize(INT_ARG(0));
            break;
        case SYS_READ:
            read(INT_ARG(0),
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
    exit(ABNORMAL_EXIT_CODE);
}


// SG_PRJ1 TODO_DONE: Define General System Calls Implementation
void
halt(void) {
    shutdown_power_off();
}

void
exit(int status) {
    // TODO exit() synchronization..?
    struct thread *t = thread_current();
    t->exit_code = status;
    printf("%s: exit(%d)\n", t->name, status);

    thread_exit();
}

int
write(int fd, const void *buffer, unsigned size) {
    if (fd == 1) { // console
        putbuf((char *) buffer, size);
        return size;
    }
    return ABNORMAL_EXIT_CODE;
}

pid_t
exec(const char *cmd_line) {
    // is_valid_string
    char *file_name = (char *) malloc(sizeof(char) * (strlen(cmd_line) + 1));
    char *tmp;
    struct file *file_obj;

    strlcpy(file_name, cmd_line, strlen(cmd_line) + 1);
    file_name = strtok_r(file_name, " ", &tmp);
    file_obj = filesys_open(file_name);
    free(file_name);

    if (!file_obj) {
        return ABNORMAL_EXIT_CODE;
    }
    file_close(file_obj);

    return process_execute(cmd_line);
}

int wait(pid_t pid) {
    return process_wait(pid);
}

bool create(const char *file, unsigned initial_size) {
    if (strlen(file) == 0) return false;
    return filesys_create(file, initial_size);
}

bool remove(const char *file) {
    return filesys_remove(file);
}

int open(const char *file UNUSED) {
    return unsupported_func();
}

int filesize(int fd UNUSED) {
    return unsupported_func();
}

int read(int fd, void *buffer, unsigned size) {
    uint8_t *console_buf;
    unsigned i;

    if (fd == 0) { // console
        console_buf = (uint8_t *) buffer;
        for (i = 0; i < size; i++) console_buf[i] = input_getc();
        return size;
    }

    return unsupported_func();
}

void seek(int fd UNUSED, unsigned position UNUSED) {
    unsupported_func();
}

unsigned tell(int fd UNUSED) {
    return unsupported_func();
}

void close(int fd UNUSED) {
    unsupported_func();
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
