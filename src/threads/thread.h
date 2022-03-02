#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "synch.h"
#include "lib/kernel/hash.h"
#ifndef USERPROG
extern bool thread_prior_aging;
#endif

/* States in a thread's life cycle. */
enum thread_status
  {
    THREAD_RUNNING,     /* Running thread. */
    THREAD_READY,       /* Not running but ready to run. */
    THREAD_BLOCKED,     /* Waiting for an event to trigger. */
    THREAD_DYING        /* About to be destroyed. */
  };

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */
#define FRACTION (1<<14)
/* A kernel thread or user process.

   Each thread structure is stored in its own 4 kB page.  The
   thread structure itself sits at the very bottom of the page
   (at offset 0).  The rest of the page is reserved for the
   thread's kernel stack, which grows downward from the top of
   the page (at offset 4 kB).  Here's an illustration:

        4 kB +---------------------------------+
             |          kernel stack           |
             |                |                |
             |                |                |
             |                V                |
             |         grows downward          |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             +---------------------------------+
             |              magic              |
             |                :                |
             |                :                |
             |               name              |
             |              status             |
        0 kB +---------------------------------+

   The upshot of this is twofold:

      1. First, `struct thread' must not be allowed to grow too
         big.  If it does, then there will not be enough room for
         the kernel stack.  Our base `struct thread' is only a
         few bytes in size.  It probably should stay well under 1
         kB.

      2. Second, kernel stacks must not be allowed to grow too
         large.  If a stack overflows, it will corrupt the thread
         state.  Thus, kernel functions should not allocate large
         structures or arrays as non-static local variables.  Use
         dynamic allocation with malloc() or palloc_get_page()
         instead.

   The first symptom of either of these problems will probably be
   an assertion failure in thread_current(), which checks that
   the `magic' member of the running thread's `struct thread' is
   set to THREAD_MAGIC.  Stack overflow will normally change this
   value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
   the run queue (thread.c), or it can be an element in a
   semaphore wait list (synch.c).  It can be used these two ways
   only because they are mutually exclusive: only a thread in the
   ready state is on the run queue, whereas only a thread in the
   blocked state is on a semaphore wait list. */
struct thread
  {
    /* Owned by thread.c. */
    tid_t tid;                          /* Thread identifier. */
    enum thread_status status;          /* Thread state. */
    char name[16];                      /* Name (for debugging purposes). */
    uint8_t *stack;                     /* Saved stack pointer. */
    int priority;                       /* Priority. */
    struct list_elem allelem;           /* List element for all threads list. */

    // base
    int base_priority;

    /* Shared between thread.c and synch.c. */
    struct list_elem elem;              /* List element. */

    // 대기 원인 락
    struct lock *wait_on_lock;

    // 우선순위 기부 리스트와 원소
    struct list donations;
    struct list_elem donation_elem;

#ifdef USERPROG
    /* Owned by userprog/process.c. */
    uint32_t *pagedir;                  /* Page directory. */
    //struct semaphore p_sema;
    //struct semaphore i_sema;

    //struct list child_list;
    //struct list_elem i_elem;
    int exit_code;
    //struct file* fd_table[128];

    //struct thread* parent;
    // struct semaphore child_execute_sema;
    int flag;

#endif
    // 부모의 자식 리스트에 들어가는 원소입니다.
    struct list_elem child_elem;

    // 현재 스레드의 자식 스레드 리스트입니다. 오직 이 스레드만이
    // 이 리스트를 변경할 것이므로 동기화하지 않아도 됩니다.
    struct list child_list;

    // 증가: 성공 여부를 따지지 않고, 적재 작업이 완료되었을 때
    // 감소: 부모 프로세스의 exec에서 적재 완료 대기
    struct semaphore load_sema;

    bool load_succeeded; // TODO rename

    // 이 프로세스의 프로그램 파일을 연 다음 쓸 수 없도록 한 것
    struct file* run_file; // TODO rename

    // 증가: 이 스레드가 종료되려고 할 때
    // 감소: 이 스레드의 종료를 "대기"하기 위하여
    struct semaphore wait_sema;

    // 증가: 이 스레드 자료 구조를 제거해도 좋을 상황이 되었을 때
    // 감소: 이 스레드 자료 구조를 "제거"하기 직전
    struct semaphore destroy_sema;

    int64_t wakeup_ticks;
    int original_priority;
    struct list lock_list;
    struct lock *donating_lock;

    //int nice;
    //int recent_cpu;
    /* Owned by thread.c. */
    unsigned magic;                     /* Detects stack overflow. */

    //void *mbuffer[130];
    // uint32_t msize[130];

    // 다음 차례에 할당될 파일 디스크립터 번호
    int next_fd;

    // 파일 디스크립터 테이블
    struct file **fd_table;

    // 이 스레드가 sleep_list의 원소일 때, 이 틱 이전에 스레드를 깨우지 않도록 합니다.
    int64_t wakeup_tick;

    // 스케줄링 정보
    int nice;
    int recent_cpu;

    // 가상 메모리 관리 해시 테이블
    struct hash vm;

    // 메모리 매핑된 파일 관리 정보
    struct list mmap_list;
    int next_mapid;

    // 작업 디렉터리입니다.
    struct dir *working_dir;

  };

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

/* Performs some operation on thread t, given auxiliary data AUX. */
typedef void thread_action_func (struct thread *t, void *aux);
void thread_foreach (thread_action_func *, void *);

int thread_get_priority (void);
void thread_set_priority (int);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

// prj3 functions
void thread_sleep_until(int64_t time);
void thread_wakeup(int64_t current_ticks);
// bool exist_high_priority_than_cur(void);
int64_t get_next_tick_to_awake (void);

int thread_get_priority (void);
void thread_set_priority (int);
bool thread_compare_priority (const struct thread *, const struct thread *);
void thread_preempt (void);

void donate_priority (struct thread *);
void refresh_priority (struct thread *, int *);
void remove_with_lock (struct thread *, struct lock *);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);
void mlfqs_priority(struct thread* t);
void update_recent_cpu(void);

void increase_cur_recent_cpu(void);
/*
void sort_ready_list(void);
void update_load_avg(void);
void thread_aging(void);
*/

// unsigned thread_get_ticks (void);

#endif /* threads/thread.h */
