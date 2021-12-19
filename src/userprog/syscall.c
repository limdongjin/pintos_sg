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
#include "threads/palloc.h"
#include "devices/shutdown.h"
#include "userprog/process.h"

#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "filesys/directory.h"

#include "devices/input.h"

#include "vm/page.h"
#include "vm/swap.h"
#include "vm/frame.h"


#ifndef DEBUG_PRINT1
 #ifdef DEBUG1
   #define DEBUG_PRINT1(fmt, args...) printf("DEBUG: %s:%d:%s, thread_name=%s, tid=%s(): " fmt, __FILE__, \
   __LINE__, __func__, thread_current()->name, thread_current()-> tid, ##args)
 #else
   #define DEBUG_PRINT1(fmt, args...) /* Don't do anything in release builds */
 #endif
#endif

//struct file
//{
//    struct inode *inode;        /* File's inode. */
//    off_t pos;                  /* Current position. */
//    bool deny_write;            /* Has file_deny_write() been called? */
// };

static void syscall_handler(struct intr_frame *);

static bool check_user_ptr(const void *user_ptr);

static bool get_arg_and_verify(void *esp, void *arg[SYSCALL_MAX_ARGC]);

static int unsupported_func(void);
struct lock file_lock;

void
syscall_init(void) {
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
    lock_init(&file_lock);
}

/*
static bool
check_user_ptr(const void *user_ptr) {
    DEBUG_PRINT1("START\n");
    if(!is_user_vaddr(user_ptr) ||
      get_page_by_(((uint32_t) user_ptr >> 12) << 12, thread_tid()) == NULL)
    {
        DEBUG_PRINT1("FAIL : Invalid\n");
	    exit(-1);
    }
    DEBUG_PRINT1("END\n");
    return true;
}

static bool
get_arg_and_verify(void *esp, void *arg[SYSCALL_MAX_ARGC]) {
    DEBUG_PRINT1("START\n");
// scope : get_arg_and_verify(..DEBUG_PR.){ ... }
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
            //printf("unsupported syscall\n");
            //return false;
	    break;
    }
#undef SAVE_ARG_AND_VERIFY
    DEBUG_PRINT1("END\n");
    return true;
}
*/

// 주소 addr이 유효한 유저 모드 주소가 아니면 프로세스를 종료합니다.
// 시스템 콜을 안전하게 수행하기 위하여 사용합니다.
static inline void
check_address (void *addr, void *esp)
{
    // 유저 영역 주소인지 확인한 다음, 올바른 가상 주소인지 확인합니다.
    if (!(
            is_user_vaddr (addr) &&
            addr >= (void *)0x08048000UL
    ))
        exit (-1);

    if (!find_vme (addr))
    {
        if (!verify_stack ((int32_t) addr, (int32_t) esp))
            exit (-1);
        expand_stack (addr);
    }
}

// 4 바이트 값에 대한 안전한 포인터인지 검사합니다.
static inline void
check_address4 (void *addr, void *esp)
{
    check_address (addr, esp);
    check_address (addr + 3, esp);
}

// 4바이트 인자를 1개에서 4개 사이에서 가져옵니다.
static inline void
get_arguments (int32_t *esp, int32_t *args, int count, void *esp2)
{
    ASSERT (1 <= count && count <= 4);
    while (count--)
    {
        check_address4 (++esp, esp2);
        *(args++) = *esp;
    }
}
// 아래 함수와 같으며, 주어진 크기를 가정합니다.
static inline void
check_user_string_l (const char *str, unsigned size, void *esp)
{
    while (size--)
        check_address ((void *) (str++), esp);
}

// 널 문자로 종료되는 사용자 문자열의 유효성을 확인합니다.
static inline void
check_user_string (const char *str, void *esp)
{
    for (; check_address ((void *) str, esp), *str; str++);
}

// 아래 함수와 같으며, 주어진 크기를 가정합니다.
static inline char *
get_user_string_l (const char *str, unsigned size)
{
    char *buffer = 0;
    buffer = malloc (size);
    if (!buffer)
        return 0;
    memcpy (buffer, str, size);
    return buffer;
}

// 사용자 문자열을 가져옵니다. 새로운 메모리를 동적 할당합니다.
static inline char *
get_user_string (const char *str)
{
    unsigned size;
    char *buffer;
    size = strlen (str) + 1;
    buffer = get_user_string_l (str, size);
    return buffer;
}
// 플래그가 맞을 때 동적 할당된 문자열을 해제하고 널 포인터를 대입합니다.
static inline void
free_single_user_string (char **args, int flag, int index)
{
    if (flag & (0b1000 >> index))
    {
        free (args[index]);
        args[index] = 0;
    }
}

// 플래그의 마지막 4비트에 따라서 문자열들을 해제합니다.
static inline void
free_user_strings (char **args, int flag)
{
    ASSERT (0 <= flag && flag <= 0b1111);
    free_single_user_string (args, flag, 0);
    free_single_user_string (args, flag, 1);
    free_single_user_string (args, flag, 2);
    free_single_user_string (args, flag, 3);
}

// 플래그가 맞을 때 사용자 문자열을 복사합니다.
// 작업 중 실패하면 내용을 되돌리고 종료합니다.
// 유효성을 검증한 다음 이 작업을 실행해야 합니다.
static inline void
get_single_user_string (char **args, int flag, int index)
{
    if (flag & (0b1000 >> index))
    {
        args[index] = get_user_string (args[index]);
        if (!args[index])
        {
            free_user_strings (args, flag & (0b11110000 >> index));
            exit(-1);
        }
    }
}

// 플래그가 맞을 때 사용자 문자열의 유효성을 확인합니다.
// 유효하지 않으면 종료합니다.
static inline void
check_single_user_string (char **args, int flag, int index, int32_t esp)
{
    if (flag & (0b1000 >> index))
        check_user_string (args[index], esp);
}

// 플래그의 마지막 4비트에 따라서 사용자 문자열을 확인하고 가져옵니다.
// 새로운 메모리를 동적 할당합니다.
static inline void
get_user_strings (char **args, int flag, void *esp)
{
    ASSERT (0 <= flag && flag <= 0b1111);
    check_single_user_string (args, flag, 0, esp);
    check_single_user_string (args, flag, 1, esp);
    check_single_user_string (args, flag, 2, esp);
    check_single_user_string (args, flag, 3, esp);
    get_single_user_string (args, flag, 0);
    get_single_user_string (args, flag, 1);
    get_single_user_string (args, flag, 2);
    get_single_user_string (args, flag, 3);
}

static void
pin_address (void *addr, bool write)
{
    struct vm_entry *vme = find_vme (addr);
    if (write && !vme->writable)
        exit (-1);
    vme->pinned = true;
    if (vme->is_loaded == false)
        handle_mm_fault (vme);
}
static void
unpin_address (void *addr)
{
    find_vme (addr)->pinned = false;
}

static void
pin_string (const char *begin, const char *end, bool write)
{
    for (; begin < end; begin += PGSIZE)
        pin_address (begin, write);
}

static void
unpin_string (const char *begin, const char *end)
{
    for (; begin < end; begin += PGSIZE)
        unpin_address (begin);
}


static void
syscall_handler(struct intr_frame *f UNUSED) {
    DEBUG_PRINT1("START\n");
    // void *syscall_arg[SYSCALL_MAX_ARGC] = {NULL,};
    bool is_success;
    int32_t args[4];
    check_address4 (f->esp, f->esp);

// scope: syscall_handler(...) { ... }
//#define INT_ARG(IDX) (*(int*)syscall_arg[IDX])
//#define CHAR_PTR_ARG(IDX) (*(char**)syscall_arg[IDX])
//#define VOID_PTR_ARG(IDX) (*(void**)syscall_arg[IDX])
//#define UNSIGNED_ARG(IDX) (*(unsigned*)syscall_arg[IDX])
//    is_success = get_arg_and_verify(f->esp, syscall_arg);

  //  if (!is_success) {
 //       DEBUG_PRINT1("FAIL : verify fail\n");
 //       f->eax = ABNORMAL_EXIT_CODE;
 //       abnormal_exit();
 //       return;
 //   }

    switch (*(int *) f->esp) {
        case SYS_HALT:
            halt();
            break;
        case SYS_EXIT:
            get_arguments(f->esp, args, 1, f->esp);
            exit(args[0]);
            break;
        case SYS_EXEC:
            get_arguments (f->esp, args, 1, f->esp);
            get_user_strings ((char **) args, 0b1000, f->esp);
            f->eax = exec ((const char *) args[0]);
            free_user_strings ((char **) args, 0b1000);
            // f->eax = exec(CHAR_PTR_ARG(0));
            break;
        case SYS_WAIT:
            get_arguments (f->esp, args, 1, f->esp);
            f->eax = wait ((tid_t) args[0]);
            // f->eax = wait(INT_ARG(0));
            break;
        case SYS_CREATE:
            get_arguments (f->esp, args, 2, f->esp);
            get_user_strings ((char **) args, 0b1000, f->esp);
            f->eax = create ((const char *) args[0], args[1]);
            free_user_strings ((char **) args, 0b1000);
            //f->eax = create(CHAR_PTR_ARG(0),
            //                 UNSIGNED_ARG(1));
            break;
        case SYS_REMOVE:
            get_arguments (f->esp, args, 1, f->esp);
            get_user_strings ((char **) args, 0b1000, f->esp);
            f->eax = remove ((const char *) args[0]);
            free_user_strings ((char **) args, 0b1000);
            //f->eax = remove(CHAR_PTR_ARG(0));
            break;
        case SYS_OPEN:
            get_arguments (f->esp, args, 1, f->esp);
            get_user_strings ((char **) args, 0b1000, f->esp);
            f->eax = open ((const char *) args[0]);
            free_user_strings ((char **) args, 0b1000);
            // check_user_ptr(CHAR_PTR_ARG(0));
            // f->eax = open(CHAR_PTR_ARG(0));
            break;
        case SYS_FILESIZE:
            get_arguments (f->esp, args, 1, f->esp);
            f->eax = filesize ((int) args[0]);
            // f->eax = filesize(INT_ARG(0));
            break;
        case SYS_READ:
            get_arguments (f->esp, args, 3, f->esp);
            check_user_string_l ((const char *) args[1], (unsigned) args[2], f->esp);
            f->eax = read ((int) args[0], (void *) args[1], (unsigned) args[2]);
            //f->eax = read(INT_ARG(0),
            //     VOID_PTR_ARG(1),
            //     UNSIGNED_ARG(2));
            break;
        case SYS_WRITE:
            get_arguments (f->esp, args, 3, f->esp);
            check_user_string_l ((const char *) args[1], (unsigned) args[2], f->esp);
            args[1] = (int) get_user_string_l ((const char *) args[1], (unsigned) args[2]);
            f->eax = write ((int) args[0], (const void *) args[1], (unsigned) args[2]);
            free ((void *) args[1]);
            args[1] = 0;
            //check_user_ptr(VOID_PTR_ARG(1));
            //f->eax = write(INT_ARG(0),
            //               VOID_PTR_ARG(1),
            //               UNSIGNED_ARG(2));
            break;
        case SYS_SEEK:
            get_arguments (f->esp, args, 2, f->esp);
            seek ((int) args[0], (unsigned) args[1]);
            //seek(INT_ARG(0),
            //     UNSIGNED_ARG(1));
            break;
        case SYS_TELL:
            get_arguments (f->esp, args, 1, f->esp);
            f->eax = tell ((int) args[0]);
            //lock_acquire(&file_lock);
            //f->eax = tell(INT_ARG(0));
            //lock_release(&file_lock);
            break;
        case SYS_CLOSE:
            get_arguments (f->esp, args, 1, f->esp);
            close ((int) args[0]);
            //close(INT_ARG(0));
            break;
        case SYS_MMAP:
            get_arguments (f->esp, args, 2, f->esp);
            f->eax = mmap ((int) args[0], (void *) args[1]);
            //check_user_ptr(VOID_PTR_ARG(1));
            //f->eax = mmap(INT_ARG(0),
            //              VOID_PTR_ARG(1));
            break;
        case SYS_MUNMAP:
            get_arguments (f->esp, args, 1, f->esp);
            munmap ((int) args[0]);
            //munmap(INT_ARG(0));
            break;
        case SYS_CHDIR:
            get_arguments (f->esp, args, 1, f->esp);
            get_user_strings ((char **) args, 0b1000, f->esp);
            f->eax = chdir ((const char *) args[0]);
            free_user_strings ((char **) args, 0b1000);
            // f->eax = chdir(CHAR_PTR_ARG(0));
            break;
        case SYS_MKDIR:
            get_arguments (f->esp, args, 1, f->esp);
            get_user_strings ((char **) args, 0b1000, f->esp);
            f->eax = mkdir ((const char *) args[0]);
            free_user_strings ((char **) args, 0b1000);

            //f->eax = mkdir(CHAR_PTR_ARG(0));
            break;
        case SYS_READDIR:
            get_arguments (f->esp, args, 2, f->esp);
            check_user_string_l ((const char *) args[1], READDIR_MAX_LEN + 1, f->esp);
            f->eax = readdir ((int) args[0], (char *) args[1]);

           // f->eax = readdir(INT_ARG(0),
           //                  CHAR_PTR_ARG(1));
            break;
        case SYS_ISDIR:
            get_arguments (f->esp, args, 1, f->esp);
            f->eax = isdir ((int) args[0]);
            //f->eax = isdir(INT_ARG(0));
            break;
        case SYS_INUMBER:
            get_arguments (f->esp, args, 1, f->esp);
            f->eax = inumber ((int) args[0]);
            // f->eax = inumber(INT_ARG(0));
            break;
        case SYS_FIBONACCI:
            f->eax = fibonacci(INT_ARG(0));
            break;
        case SYS_MAX_OF_FOUR_INT:
            f->eax = max_of_four_int(INT_ARG(0), INT_ARG(1), INT_ARG(2), INT_ARG(3));
            break;
        default:
            // printf("unsupported syscall\n");
            exit(-1);
    }
    // thread_exit ();
//#undef INT_ARG
//#undef CHAR_PTR_ARG
//#undef VOID_PTR_ARG
//#undef UNSIGNED_ARG
    DEBUG_PRINT1("END\n");
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
    DEBUG_PRINT1("START\n");
    //int i;
    //struct list_elem* e = NULL;

    thread_current()->exit_code = status;
    printf("%s: exit(%d)\n", thread_name(), status);

/*    i = 3;
    while(i < 128 && thread_current()->fd_table[i] != NULL) {
        struct file *f = thread_current()->fd_table[i];
        if(f != NULL) {
            if (thread_current()->mbuffer[i] != NULL)
                munmap(i);
            close(i++);
        }
    }

    for(e = list_begin(&thread_current()->child_list);
        e != list_end(&thread_current()->child_list);
        e = list_next(e))
    {
        process_wait(list_entry(e, struct thread, i_elem)->tid);
    }*/

    DEBUG_PRINT1("END : before thread_exit() \n");
    thread_exit();
}

int
write(int fd, const void *buffer, unsigned size) {
    DEBUG_PRINT1("START\n");
    if(fd == 0 || fd == 2) {
        DEBUG_PRINT1("FAIL : since fd == 0 or fd == 2\n");
        abnormal_exit();
    }
    struct file* cfp;

    check_user_ptr(buffer);
    int ret;
    bool success = true;
    lock_acquire(&file_lock);
    DEBUG_PRINT1("lock acquire\n");
    pinning(buffer, size);
    if (fd == 1) { // console
        putbuf((char *) buffer, size);
        ret = size;
        goto write_done;
    }

    if(thread_current()->fd_table[fd] == NULL){
        DEBUG_PRINT1("FAIL : fd_table[fd] == NULL\n");
        success = false;
        goto write_done;
    }

     cfp = thread_current()->fd_table[fd];
     if(cfp->deny_write) file_deny_write(cfp);
     ret = file_write(thread_current()->fd_table[fd], buffer, size);
     unpinning(buffer, size);
  write_done:
     lock_release(&file_lock);
    DEBUG_PRINT1("lock release\n");

    if(!success) {
        DEBUG_PRINT1("FAIL : write result is invalid\n");
        exit(-1);
    }
    DEBUG_PRINT1("END");
     return ret;
}

pid_t
exec(const char *cmd_line) {
    DEBUG_PRINT1("START\n");
    //char file_name[130];
    //struct file *fp;
    //int i = 0;
    struct thread* child;
    pid_t ret;

    //while(cmd_line[i] != ' ' && (file_name[i] = cmd_line[i]) != '\0') i++;
    //file_name[i] = '\0';

    //lock_acquire(&file_lock);
    //fp = filesys_open(file_name);
    //lock_release(&file_lock);

    //if (fp == NULL) return ABNORMAL_EXIT_CODE;

    //lock_acquire(&file_lock);
    //file_close(fp);
    //lock_release(&file_lock);

    if((ret = process_execute(cmd_line)) == TID_ERROR){
        DEBUG_PRINT1("FAIL : TID_ERROR\n");
        return TID_ERROR;
    }

    // thread_current()->load
    child = thread_get_child (ret);
    ASSERT (child);

    sema_down (&child->load_sema);

    // 여기에서 실패하면 프로그램 적재 실패입니다.
    if (!child->load_succeeded)
        return TID_ERROR;

    DEBUG_PRINT1("END\n");
    return ret;
}

int
wait(pid_t pid) {
    return process_wait(pid);
}

bool
create(const char *file, unsigned initial_size) {
    DEBUG_PRINT1("START");

/*     if(file == NULL) {
         DEBUG_PRINT1("FAIL : file == NULL ");
         exit(-1);
     }

    check_user_ptr(file);
    lock_acquire(&file_lock);

    DEBUG_PRINT1("lock acquire\n");
    bool ret = filesys_create(file, initial_size);

    lock_release(&file_lock);

    DEBUG_PRINT1("lock release\n");
    */

    DEBUG_PRINT1("END : before call filesys_create(..)\n");
    return filesys_create(file, initial_size);
}

bool
remove(const char *file) {
     /*if(file == NULL) exit(-1);
     check_user_ptr(file);

    lock_acquire(&file_lock);
    bool ret = filesys_remove(file);
    lock_release(&file_lock);
*/
    return filesys_remove(file);
}

int
open(const char *file UNUSED) {
    DEBUG_PRINT1("START\n");
    /*
    if(file == NULL) {
        DEBUG_PRINT1("END : file == NULL\n");
	    exit(-1);
    }
    int i, ret = -1;

    lock_acquire(&file_lock);
    DEBUG_PRINT1("lock acquire\n");
    struct file* fp = filesys_open(file);
    if(fp == NULL) {
        DEBUG_PRINT1("FAIL : fp == NULL\n");
	    goto open_done;
    }
    i = 3;
    while(i < 128 && thread_current()->fd_table[i] != NULL) i++;
    if(i < 128){
        if(strcmp(thread_name(), file) == 0) file_deny_write(fp);
        thread_current()->fd_table[i] = fp;
        ret = i;
    }
 open_done:
    lock_release(&file_lock);
    DEBUG_PRINT1("lock release\n");
*/
    int ret = -1;
    lock_acquire(&file_lock);
    ret = process_add_file(filesys_open(file));
    lock_release(&file_lock);

    DEBUG_PRINT1("END\n");
    return ret;
}

int
filesize(int fd UNUSED) {

    // DEBUG_PRINT1("START\n");
    /*
    lock_acquire(&file_lock);

    DEBUG_PRINT1("lock acquire\n");
    if(thread_current()->fd_table[fd] == NULL) {
        DEBUG_PRINT1("FAIL : fp == NULL\n");
        DEBUG_PRINT1("lock release\n");
        lock_release(&file_lock);
        exit(-1);
    }
    int ret = (int) file_length(thread_current()->fd_table[fd]);
    lock_release(&file_lock);

    DEBUG_PRINT1("lock release\n");
     */
    struct file *f = process_get_file (fd);
    if (f == NULL)
        return -1;
    return file_length (f);
    //DEBUG_PRINT1("END\n");
    // return ret;
}

int
read(int fd, void *buffer, unsigned size) {
    // DEBUG_PRINT1("START\n");
    /*
    unsigned i = 0;
    bool success = true;
    check_user_ptr(buffer);
    if(fd == 1 || fd == 2) {
        DEBUG_PRINT1("FAIL : fd == 1 or 2\n");
        abnormal_exit();
    }

    lock_acquire(&file_lock);
    DEBUG_PRINT1("lock acquire\n");
    if (fd == 0) { // console
        while(i < size && input_getc() != '\0' && i++);
        goto read_done;
    }

    if(thread_current()->fd_table[fd] == NULL){
        DEBUG_PRINT1("FAIL : fd_table[fd] == NULL\n");
        success = false;
        goto read_done;
    }
    pinning(buffer, size);
    i = file_read(thread_current()->fd_table[fd], buffer, size);
    unpinning(buffer, size);
 read_done:
    lock_release(&file_lock);
    DEBUG_PRINT1("lock release\n");
    if(!success) {
        DEBUG_PRINT1("FAIL : read result invalid\n");
        exit(-1);
    }

    DEBUG_PRINT1("END\n");
     */
    struct file *f;
    pin_string (buffer, buffer + size, true);
    lock_acquire (&file_lock);

    if (fd == STDIN_FILENO)
    {
        // 표준 입력
        unsigned count = size;
        while (count--)
            *((char *)buffer++) = input_getc();
        lock_release (&file_lock);
        unpin_string (buffer, buffer + size);
        return size;
    }
    if ((f = process_get_file (fd)) == NULL)
    {
        lock_release (&file_lock);
        unpin_string (buffer, buffer + size);
        return -1;
    }
    size = file_read (f, buffer, size);
    lock_release (&file_lock);
    unpin_string (buffer, buffer + size);
    return size;
}

void
seek(int fd UNUSED, unsigned position UNUSED) {
    DEBUG_PRINT1("START\n");
    /*
    if(fd >= 128) {
        DEBUG_PRINT1("FAIL : fd >= 128\n");
        exit(-1);
    }
    ASSERT(fd >= 0);

    lock_acquire(&file_lock);
    DEBUG_PRINT1("lock acquire\n");
    if(thread_current()->fd_table[fd] == NULL) {
        DEBUG_PRINT1("FAIL : fd_table[fd] == NULL\n");
        DEBUG_PRINT1("lock release\n");
        lock_release(&file_lock);
        abnormal_exit();
    }

    file_seek(thread_current()->fd_table[fd], position);
    lock_release(&file_lock);
    DEBUG_PRINT1("lock release\n");*/
    struct file *f = process_get_file (fd);
    if (f == NULL)
        return;
    file_seek (f, position);
    DEBUG_PRINT1("END\n");
}

unsigned
tell(int fd UNUSED) {
    DEBUG_PRINT1("START\n");
    /*if(fd >= 128) {
        DEBUG_PRINT1("FAIL : fd >= 128\n");
        exit(-1);
    }

    lock_acquire(&file_lock);
    DEBUG_PRINT1("lock acquire\n");
    if(thread_current()->fd_table[fd] == NULL) {
        DEBUG_PRINT1("FAIL : fd_table[fd] == NULL");
        lock_release(&file_lock);
        DEBUG_PRINT1("lock release\n");
        exit(-1);
    }
    unsigned ret = (unsigned ) file_tell(thread_current()->fd_table[fd]);
    lock_release(&file_lock);
    DEBUG_PRINT1("lock release\n");
    DEBUG_PRINT1("END");
     */
    struct file *f = process_get_file (fd);
    if (f == NULL)
        exit (-1);
    return file_tell (f);
    // return ret;
}

void
close(int fd UNUSED) {
    DEBUG_PRINT1("START\n");
    /*
    if(fd >= 128) {
        DEBUG_PRINT1("FAIL : fd >= 128\n");
        exit(-1);
    }

    lock_acquire(&file_lock);
    DEBUG_PRINT1("lock acquire\n");
    struct file* fp = thread_current()->fd_table[fd];

    if(fp == NULL) {
        DEBUG_PRINT1("FAIL : fd_table[fd] == NULL\n");
        lock_release(&file_lock);
        DEBUG_PRINT1("lock release\n");
        abnormal_exit();
    }

    file_close(fp);
    thread_current()->fd_table[fd] = NULL;
    lock_release(&file_lock);
    DEBUG_PRINT1("lock release\n");
     */
    process_close_file (fd);
    DEBUG_PRINT1("END\n");
}

/* Project 3 and optionally project 4. */

mapid_t
mmap(int fd UNUSED, void *addr UNUSED) {
    // DEBUG_PRINT1("START\n");

    struct mmap_file *mmap_file;
    size_t offset = 0;

    if (pg_ofs (addr) != 0 || !addr)
        return -1;
    if (is_user_vaddr (addr) == false)
        return -1;
    mmap_file = (struct mmap_file *)malloc (sizeof (struct mmap_file));
    if (mmap_file == NULL)
        return -1;
    memset (mmap_file, 0, sizeof(struct mmap_file));
    list_init (&mmap_file->vme_list);
    if (!(mmap_file->file = process_get_file (fd)))
        return -1;
    mmap_file->file = file_reopen(mmap_file->file);
    mmap_file->mapid = thread_current ()->next_mapid++;
    list_push_back (&thread_current ()->mmap_list, &mmap_file->elem);

    int length = file_length (mmap_file->file);
    while (length > 0)
    {
        if (find_vme (addr))
            return -1;

        struct vm_entry *vme = (struct vm_entry *)malloc (sizeof (struct vm_entry));
        memset (vme, 0, sizeof (struct vm_entry));
        vme->type = VM_FILE;
        vme->writable = true;
        vme->vaddr = addr;
        vme->offset = offset;
        vme->read_bytes = length < PGSIZE ? length : PGSIZE;
        vme->zero_bytes = 0;
        vme->file = mmap_file->file;

        list_push_back (&mmap_file->vme_list, &vme->mmap_elem);
        insert_vme (&thread_current ()->vm, vme);
        addr += PGSIZE;
        offset += PGSIZE;
        length -= PGSIZE;
    }
    return mmap_file->mapid;

    /*
    lock_acquire (&file_lock);
    DEBUG_PRINT1("lock acquire\n");
    mapid_t ret = fd;
    size_t read_bytes, zero_bytes, p_read_bytes, p_zero_bytes;
    uint8_t *va, *pa;
    struct file *fp = file_reopen(thread_current()->fd_table[fd]);

    ASSERT (fp != NULL);

    if ((uint32_t) addr % PGSIZE != 0) {
        DEBUG_PRINT1("FAIL : addr invalid\n");
        ret = -1;
        goto DONE;
        // return -1;
    }

    read_bytes = file_length (fp);
    zero_bytes = PGSIZE - (read_bytes % PGSIZE);
    va = addr;

    thread_current()->msize[fd] = read_bytes;

    file_seek (fp, 0);

    while (read_bytes > 0 || zero_bytes > 0) {
        if(read_bytes < PGSIZE) p_read_bytes = read_bytes;
        else p_read_bytes = PGSIZE;
        p_zero_bytes = PGSIZE - p_read_bytes;

        while ((pa = palloc_get_page(PAL_USER)) == NULL)
            evict_frame();

        if (file_read (fp, pa, p_read_bytes) != (int) p_read_bytes) {
            DEBUG_PRINT1("FAIL : file_read != p_read_bytes\n");
            palloc_free_page (pa);
            ret = -1;
            goto DONE;
        }

        memset (pa + p_read_bytes, 0, p_zero_bytes);
        pagedir_set_page(thread_current()->pagedir,
                         va,
                         pa,
                         true);
        insert_page(va, pa, true);

        read_bytes -= p_read_bytes;
        zero_bytes -= p_zero_bytes;
        va += PGSIZE;
    }
    thread_current()->mbuffer[fd] = addr;
DONE:
    lock_release (&file_lock);
    DEBUG_PRINT1("lock release\n");
    DEBUG_PRINT1("END\n");
    return ret;
     */
}

void
munmap(mapid_t t UNUSED) {
    DEBUG_PRINT1("START\n");

    /*
    if(t < 0) {
        DEBUG_PRINT1("FAIL : t < 0\n");
        exit(-1);
    }

    void *buffer = thread_current()->mbuffer[t];
    ASSERT (buffer != NULL);
    int size = filesize(t);

    lock_acquire (&file_lock);

    DEBUG_PRINT1("lock acquire\n");

    pinning(buffer, size);

    file_write (thread_current()->fd_table[t], buffer, size);

    unpinning(buffer, size);
    lock_release (&file_lock);

    DEBUG_PRINT1("lock release\n");
     */

    struct mmap_file *f = find_mmap_file (mapid);
    if (!f)
        return;
    do_mummap (f);
    DEBUG_PRINT1("END\n");
}

/* Project 4 only. */
bool
chdir(const char *dir UNUSED) {
    /*
    return unsupported_func();*/
    char path[PATH_MAX_LEN + 1];
    strlcpy (path, path_o, PATH_MAX_LEN);
    strlcat (path, "/0", PATH_MAX_LEN);

    char name[PATH_MAX_LEN + 1];
    struct dir *dir = parse_path (path, name);
    if (!dir)
        return false;
    dir_close (thread_current ()->working_dir);
    thread_current ()->working_dir = dir;
    return true;
}

bool
mkdir(const char *dir UNUSED) {
    return filesys_create_dir (dir);

    // return unsupported_func();
}

bool
readdir(int fd UNUSED, char name[READDIR_MAX_LEN + 1] UNUSED) {
    // 파일 디스크립터를 이용하여 파일을 찾습니다.
    struct file *f = process_get_file (fd);
    if (f == NULL)
        exit (-1);
    // 내부 아이노드 가져오기 및 디렉터리 열기
    struct inode *inode = file_get_inode (f);
    if (!inode || !inode_is_dir (inode))
        return false;
    struct dir *dir = dir_open (inode);
    if (!dir)
        return false;
    int i;
    bool result = true;
    off_t *pos = (off_t *)f + 1;
    for (i = 0; i <= *pos && result; i++)
        result = dir_readdir (dir, name);
    if (i <= *pos == false)
        (*pos)++;
    return result;
    // return unsupported_func();
}

bool
isdir(int fd UNUSED) {
    // 파일 디스크립터를 이용하여 파일을 찾습니다.
    struct file *f = process_get_file (fd);
    if (f == NULL)
        exit (-1);
    // 디렉터리인지 계산하여 반환합니다.
    return inode_is_dir (file_get_inode (f));

    // return unsupported_func();
}

int
inumber(int fd UNUSED) {
    // 파일 디스크립터를 이용하여 파일을 찾습니다.
    struct file *f = process_get_file (fd);
    if (f == NULL)
        exit (-1);
    return inode_get_inumber (file_get_inode (f));

    // return unsupported_func();
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
