#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "filesys/directory.h"

#ifdef USERPROG

#include "userprog/process.h"

#endif

//#ifndef DEBUG_PRINT
//#ifdef DEBUG
//#define DEBUG_PRINT(fmt, args...) printf("DEBUG: %s:%d:%s(): " fmt, __FILE__, __LINE__, __func__, ##args)
//#else
//#define DEBUG_PRINT(fmt, args...) /* Don't do anything in release builds */
//#endif
//#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

#define NICE_DEFAULT 0
#define RECENT_CPU_DEFAULT 0
#define LOAD_AVG_DEFAULT 0

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/* List of all processes.  Processes are added to this list
   when they are first scheduled and removed when they exit. */
static struct list all_list;

// 타이머 대기를 이유로 블록된 스레드들의 리스트입니다.
static struct list sleep_list;

// 리스트의 sleep_list의 스레드에서 가장 이른 next_tick_to_awake입니다.
// 만약 타이머 대기 중인 스레드가 없다면 INT64_MAX로 지정됩니다.
static int64_t next_tick_to_awake = INT64_MAX;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Stack frame for kernel_thread(). */
struct kernel_thread_frame {
    void *eip;                  /* Return address. */
    thread_func *function;      /* Function to call. */
    void *aux;                  /* Auxiliary data for function. */
};

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */
int load_avg;

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */
#ifndef USERPROG
bool thread_prior_aging;
#endif
/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static struct list sleep_list;

static void kernel_thread(thread_func *, void *aux);

static void idle(void *aux UNUSED);

static struct thread *running_thread(void);

static struct thread *next_thread_to_run(void);

static void init_thread(struct thread *, const char *name, int priority);

static bool is_thread(struct thread *) UNUSED;

static void *alloc_frame(struct thread *, size_t size);

static void schedule(void);

void thread_schedule_tail(struct thread *prev);

static tid_t allocate_tid(void);

// refer lib/kernel/list.h list_less_func
static bool sleep_list_less_func(const struct list_elem *a,
                                 const struct list_elem *b,
                                 void *aux UNUSED);
static bool ready_list_greater_func(const struct list_elem *a,
                                    const struct list_elem *b,
                                    void *aux UNUSED);

// BSD scheduler formula
static int calc_new_priority(int recent_cpu, int nice);
static int calc_new_recent_cpu(int recent_cpu, int nice, int load_avg);

// fixed point operators
#define N_TO_FP(n) (n*FRACTION)
#define X_TO_NEAREST_INT(x) ((x > 0) ? ((x + FRACTION / 2)/FRACTION) : ((x - FRACTION/2)/FRACTION) )
#define TRUNCATE(x) (x/FRACTION)
// #define ADD_FP_FP(x, y) (x + y)
#define ADD_FP_INT(x, n) (x + n*FRACTION)
// #define SUB_FP_FP(x, y) (x - y)
// #define SUB_FP_INT(x, n) (x - n*FRACTION)
#define MUL_FP_FP(x, y) (((int64_t)x)*y / FRACTION)
#define MUL_FP_INT(x, n) (x*n)
#define DIV_FP_FP(x, y) (((int64_t)x)*FRACTION / y)
#define DIV_FP_INT(x, n) (x/n)

unsigned thread_get_ticks () {
    return thread_ticks;
}

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init(void) {
    // DEBUG_PRINT("START\n");
    ASSERT (intr_get_level() == INTR_OFF);
    //int i;
    lock_init(&tid_lock);
    list_init(&ready_list);
    list_init(&all_list);

    // for thread project
    list_init(&sleep_list);

    /* Set up a thread structure for the running thread. */
    initial_thread = running_thread();
    init_thread(initial_thread, "main", PRI_DEFAULT);
    initial_thread->status = THREAD_RUNNING;
    initial_thread->tid = allocate_tid();
    initial_thread->nice = 0;
    initial_thread->recent_cpu = 0;

// PRJ4
 //   for(i=0;i<130;i++){
 //       initial_thread->msize[i] = 0;
 //       initial_thread->mbuffer[i] = NULL;
 //   }
    // DEBUG_PRINT("END : tid = %d\n", initial_thread->tid);
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start(void) {
    /* Create the idle thread. */
    struct semaphore idle_started;
    sema_init(&idle_started, 0);
    thread_create("idle", PRI_MIN, idle, &idle_started);
    load_avg = 0;

    /* Start preemptive thread scheduling. */
    intr_enable();

    /* Wait for the idle thread to initialize idle_thread. */
    sema_down(&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick(void) {
    struct thread *t = thread_current();

    /* Update statistics. */
    if (t == idle_thread)
        idle_ticks++;
#ifdef USERPROG
    else if (t->pagedir != NULL)
        user_ticks++;
#endif
    else
        kernel_ticks++;

    /* Enforce preemption. */
    if (++thread_ticks >= TIME_SLICE)
        intr_yield_on_return();

}

/* Prints thread statistics. */
void
thread_print_stats(void) {
    printf("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
           idle_ticks, kernel_ticks, user_ticks);
}

static int
calc_new_priority (int recent_cpu, int nice)
{
    int ret = PRI_MAX - TRUNCATE(DIV_FP_INT(recent_cpu, 4)) - 2*nice;
    // PRI_MAX - (recent_cpu / 4) - 2*nice;

    if(ret > PRI_MAX) ret = PRI_MAX;
    if(ret < PRI_MIN) ret = PRI_MIN;

    return ret;
}

static int
calc_new_recent_cpu (int recent_cpu, int nice, int load_avg)
{
   int ret;
   ret = MUL_FP_INT(load_avg, 2); // load_avg * 2
   ret = DIV_FP_FP(ret, ADD_FP_INT(ret, 1)); // (load_avg*2) / (load_avg*2 + 1)
   ret = ADD_FP_INT(MUL_FP_FP(ret, recent_cpu), nice); 
   
   return ret;
}


void
update_load_avg ()
{
  int ready_threads = list_size(&ready_list);
  if(thread_current() != idle_thread) ready_threads++;
  ready_threads = N_TO_FP(ready_threads);

  load_avg = ((59*load_avg) + ready_threads)/60;
  if(load_avg < 0) load_avg = 0;
}

void mlfqs_priority (struct thread *t)
{
    if (t == idle_thread)
        return;
    //int priority = int_to_fp (PRI_MAX);
    //int p2 = div_mixed (t->recent_cpu, 4);
    //int p3 = mult_mixed (int_to_fp (t->nice), 2);
    //priority = sub_fp (priority, p2);
    //priority = sub_fp (priority, p3);
    t->priority = calc_new_priority(t->recent_cpu, t->nice);
}

void
update_recent_cpu () // mlfqs_recalc
{
  struct thread* t;
  struct list_elem* e;

  update_load_avg();
  for(e = list_begin(&all_list);
      e != list_end(&all_list);
      e = list_next(e))
  {
      t = list_entry(e, struct thread, allelem);
      if(t == idle_thread) continue;
      t->recent_cpu = calc_new_recent_cpu(t->recent_cpu, t->nice, load_avg);
      t->priority = calc_new_priority(t->recent_cpu, t->nice);
  }
}

/*
void
thread_aging ()
{
  struct thread* t;
  struct list_elem* e;
  for(e = list_begin(&all_list);
      e != list_end(&all_list);
      e = list_next(e))
  {
    t = list_entry(e, struct thread, allelem);
    t->priority = calc_new_priority(t->recent_cpu, t->nice);
  }
} */

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create(const char *name, int priority,
              thread_func *function, void *aux) {
    // DEBUG_PRINT("START %d\n", name);
    struct thread *t;
    struct kernel_thread_frame *kf;
    struct switch_entry_frame *ef;
    struct switch_threads_frame *sf;
    tid_t tid;
    enum intr_level old_level;

    ASSERT (function != NULL);

    /* Allocate thread. */
    t = palloc_get_page(PAL_ZERO);
    if (t == NULL)
        return TID_ERROR;

    /* Initialize thread. */
    init_thread(t, name, priority);
    tid = t->tid = allocate_tid();
    vm_init(&t->vm);

// 파일 디스크립터 테이블을 할당하고 초기화합니다.
    // 이 테이블을 초과하면 어떻게 될지는 생각하지 않기로 합니다.
    t->fd_table = palloc_get_multiple (PAL_ZERO, 2);
    if (t->fd_table == NULL)
    {
        // 되돌리기
        palloc_free_page (t);
        return TID_ERROR;
    }
    // 표준 입력과 표준 출력이 먼저 fd를 점유합니다.
    t->next_fd = 2;
    // 메모리 절약하기
    t->fd_table -= t->next_fd;

    list_init (&t->mmap_list);
    t->next_mapid = 1;

    // 현재 프로세스의 작업 디렉터리가 NULL이 아니면
    // 디렉터리를 다시 열어 자식 프로세스의 작업 디렉터리로 합니다.
    if (thread_current ()->working_dir)
    {
        t->working_dir = dir_reopen(thread_current ()->working_dir);
    }

    // 현재 프로세스의 자식 프로세스 목록에 새 프로세스를 추가합니다.
    list_push_back (&thread_current ()->child_list, &t->child_elem);

///////////////////////////
    /* Prepare thread for first run by initializing its stack.
       Do this atomically so intermediate values for the 'stack'
       member cannot be observed. */
    old_level = intr_disable ();
    kf = alloc_frame(t, sizeof *kf);
    kf->eip = NULL;
    kf->function = function;
    kf->aux = aux;

    /* Stack frame for switch_entry(). */
    ef = alloc_frame(t, sizeof *ef);
    ef->eip = (void (*)(void)) kernel_thread;

    /* Stack frame for switch_threads(). */
    sf = alloc_frame(t, sizeof *sf);
    sf->eip = switch_entry;
    sf->ebp = 0;

    intr_set_level (old_level);

    /* Add to run queue. */
    thread_unblock(t);
//#ifndef USERPROG
    //if(exist_high_priority_than_cur()) {
//#endif
        // DEBUG_PRINT("yield\n");
        //thread_yield();
    //}
    thread_preempt();

    // DEBUG_PRINT("END : tid = %d\n", tid);
    return tid;
}

// 현재 스레드의 자식 스레드 중 tid가 일치하는 것을 찾습니다.
// 그러한 스레드가 없다면 NULL을 반환합니다.
struct thread *
thread_get_child (tid_t tid)
{
    struct list_elem *e;
    for (e = list_begin (&thread_current ()->child_list);
         e != list_end (&thread_current ()->child_list);
         e = list_next (e))
    {
        struct thread *t = list_entry (e, struct thread, child_elem);
        // 같은 것을 찾았으면 바로 반환합니다.
        if (t->tid == tid)
            return t;
    }
    // 찾지 못했습니다.
    return NULL;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block(void) {
    ASSERT (!intr_context());
    ASSERT (intr_get_level() == INTR_OFF);

    thread_current()->status = THREAD_BLOCKED;
    schedule();
}

static bool
ready_list_greater_func (const struct list_elem *a,
                         const struct list_elem *b,
                         void *aux UNUSED)
{
    return list_entry(a, struct thread, elem)->priority
            > list_entry(b, struct thread, elem)->priority;
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock(struct thread *t) {
    enum intr_level old_level;

    ASSERT (is_thread(t));

    old_level = intr_disable();
    ASSERT (t->status == THREAD_BLOCKED);
    list_insert_ordered(&ready_list, &t->elem, ready_list_greater_func, NULL);
    t->status = THREAD_READY;
    intr_set_level(old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name(void) {
    return thread_current()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current(void) {
    struct thread *t = running_thread();

    /* Make sure T is really a thread.
       If either of these assertions fire, then your thread may
       have overflowed its stack.  Each thread has less than 4 kB
       of stack, so a few big automatic arrays or moderate
       recursion can cause stack overflow. */
    ASSERT (is_thread(t));
    ASSERT (t->status == THREAD_RUNNING);

    return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid(void) {
    return thread_current()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) {
    struct list_elem *child;
    ASSERT (!intr_context());

#ifdef USERPROG
    process_exit();
#endif
    // 지금까지 이 프로세스가 wait하지 않은 모든 자식 프로세스가
    // 이 프로세스와 상관없이 종료될 수 있도록 합니다.
    for (child = list_begin (&thread_current ()->child_list);
         child != list_end (&thread_current ()->child_list); )
    {
        struct thread *t = list_entry (child, struct thread, child_elem);
        child = list_remove (child);
        sema_up (&t->destroy_sema);
    }

    ASSERT (thread_current()->wait_on_lock == NULL);

    // 부모 프로세스의 wait를 재개할 수 있도록 합니다.
    sema_up (&thread_current ()->wait_sema);

    // 부모 프로세스의 wait 완료 또는 부모 프로세스의 종료가
    // 일어나기를 기다립니다.
    sema_down (&thread_current ()->destroy_sema);

    /* Remove thread from all threads list, set our status to dying,
       and schedule another process.  That process will destroy us
       when it calls thread_schedule_tail(). */
    intr_disable();
    list_remove(&thread_current()->allelem);
    thread_current()->status = THREAD_DYING;
    schedule();
    NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void) {
    struct thread *cur = thread_current();
    enum intr_level old_level;

    ASSERT (!intr_context());

    old_level = intr_disable();
    if(cur != idle_thread)
        list_insert_ordered(&ready_list, &cur->elem, ready_list_greater_func, NULL);
    cur->status = THREAD_READY;
    schedule();
    intr_set_level(old_level);
}

/* Invoke function 'func' on all threads, passing along 'aux'.
   This function must be called with interrupts off. */
void
thread_foreach (thread_action_func *func, void *aux) {
    struct list_elem *e;

    ASSERT (intr_get_level() == INTR_OFF);

    for (e = list_begin(&all_list); e != list_end(&all_list);
         e = list_next(e)) {
        struct thread *t = list_entry (e, struct thread, allelem);
        func(t, aux);
    }
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority) {
    if(thread_mlfqs) return;
    intr_disable();
    struct thread* cur = thread_current();

    // 스레드의 기본 우선순위를 지정합니다.
    thread_current ()->priority = thread_current ()->base_priority = new_priority;

    // 우선순위 기부를 고려한 스레드의 적용 우선순위를 계산합니다.
    refresh_priority (thread_current (), &thread_current ()->priority);
    // 이 스레드에서 출발하는 우선순위 기부 상태를 갱신합니다.
    donate_priority (thread_current ());

    intr_enable();

    // 선점할 수 있도록 합니다.
    thread_preempt ();

    //if(cur->priority < new_priority || cur->priority == cur->original_priority)
    //    cur->priority = new_priority;
    //cur->original_priority = new_priority;
    //if(exist_high_priority_than_cur()){
    //    thread_yield();
    //}
}

/* Returns the current thread's priority. */
int
thread_get_priority (void) {
    //enum intr_level old_level = intr_disable();
    //int p = thread_current()->priority;
    //intr_set_level(old_level);
    return thread_current()->priority;
}

// 선점 스케줄링을 수행합니다. 커널은 선점 가능성이 있는 상황에 이 함수를 호출하여야 합니다.
// 이 함수는 ready_list가 정렬되어 있다고 가정합니다.
void
thread_preempt (void)
{
    enum intr_level old_level;
    old_level = intr_disable ();

    // 대기 리스트가 비어 있으면 이 스레드를 제외하고 idle 스레드 하나 뿐입니다.
    if (!list_empty (&ready_list) &&
        thread_current ()->priority
        < list_entry (list_front (&ready_list), struct thread, elem)->priority)
    {
        // 리스트의 첫 번째 스레드가 이 스레드보다 우선 실행되어야 하므로, 스케줄 반납합니다.
        intr_set_level (old_level);
        thread_yield ();
    }
    intr_set_level (old_level);
}

// 간접적인 경우를 포함하여 이 스레드의 대기 원인이 되는 락을 잡은 모든 스레드에 대하여
// 우선순위 기부를 수행합니다. 기부할 수 있는 최대 스레드 수 또는 깊이 제한은 없습니다.
void
donate_priority (struct thread *cur)
{
    struct thread *holder;

    if (thread_mlfqs)
        NOT_REACHED ();

    for (; cur->wait_on_lock && (holder = cur->wait_on_lock->holder); cur = holder)
        refresh_priority (holder, &holder->priority);
}

// 이 스레드가 잡은 락이 직접 또는 간접적으로 풀리기를 기다리는 모든 스레드를 검사하면서,
// 이 스레드보다 높은 우선순위가 있는 경우 기부를 받도록 합니다.
// 원래 스레드의 적용 우선순위에 대한 참조를 priority로 넣으십시오.
// 이 함수는 재귀적으로 수행되고 최대 깊이를 제한하지 않으므로 데드락 상황에서 위험합니다.
void
refresh_priority (struct thread *cur, int *priority)
{
    struct list_elem *e;

    if (thread_mlfqs)
        NOT_REACHED ();

    // 우선순위 갱신
    if (*priority <= cur->priority)
        *priority = cur->priority;
    else
        // 갱신될 여지가 없습니다.
        return;

    for (e = list_begin (&cur->donations); e != list_end (&cur->donations);
         e = list_next (e))
    {
        struct thread *t = list_entry (e, struct thread, donation_elem);
        // 재귀적으로 계속 수행합니다.
        refresh_priority (t, priority);
    }
}

// 이 스레드가 잡은 락이 풀리기를 기다리는 모든 스레드들을 대기 목록에서 제거합니다.
void
remove_with_lock (struct thread *cur, struct lock *lock)
{
    struct list_elem *e;

    if (thread_mlfqs)
        NOT_REACHED ();

    for (e = list_begin (&cur->donations); e != list_end (&cur->donations); )
    {
        struct thread *t = list_entry (e, struct thread, donation_elem);
        remove_with_lock (t, lock);
        if (t->wait_on_lock == lock)
            e = list_remove (e);
        else e = list_next (e);
    }
}

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice) {
    intr_disable();
    thread_current ()->nice = nice;
    intr_enable();

    //if(thread_current() == idle_thread) return;

    //struct thread* cur = thread_current();
    //cur->priority = calc_new_priority(cur->recent_cpu, nice);
    //cur->nice = nice;
    //if(exist_high_priority_than_cur()) thread_yield();
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void) {
    intr_disable();
    int nice = thread_current()->nice;
    intr_enable();
    return nice;
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void) {
  intr_disable();
  int ret = X_TO_NEAREST_INT((100*load_avg));

  intr_enable();
  return ret;
}

void
increase_cur_recent_cpu () {
  if(thread_current() != idle_thread)
    thread_current()->recent_cpu += N_TO_FP(1);
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) {
    intr_disable();
    int ret = X_TO_NEAREST_INT(100* thread_current()->recent_cpu);
    intr_enable();

    return ret;
}

static bool
sleep_list_less_func (const struct list_elem *a,
                     const struct list_elem *b,
                     void *aux UNUSED)
{
    return list_entry(a, struct thread, elem)->wakeup_ticks
              < list_entry(b, struct thread, elem)->wakeup_ticks;
}
// 커널은 타이머 대기 중인 스레드의 깨우기 목표 틱 중에서
// 가장 빨리 도래하는 스레드의 깨우기 목표 틱을 계속 유지합니다.
// 그 값을 갱신합니다.
static void
update_next_tick_to_awake (int64_t tick)
{
    // 지금 들어온 값이 더 빠르면, 갱신합니다.
    next_tick_to_awake = (next_tick_to_awake > tick) ? tick : next_tick_to_awake;
}

// update_next_tick_to_awake에서 설명한 틱 값을 반환합니다.
int64_t
get_next_tick_to_awake (void)
{
    return next_tick_to_awake;
}
void
thread_sleep_until (int64_t time)
{
    struct thread *cur;
    enum intr_level old_level;

    old_level = intr_disable ();
    cur = thread_current ();

    // idle 스레드는 sleep되지 않아야 하며,
    // 해당 스레드 코드는 이 함수를 호출하지 않습니다.
    ASSERT (cur != idle_thread);

    // 아무 스레드를 깨워야 하는 가장 이른 틱을 갱신합니다.
    update_next_tick_to_awake (cur->wakeup_tick = time);

    // 타이머 대기 리스트에 이 스레드를 추가합니다.
    list_push_back (&sleep_list, &cur->elem);
    thread_block ();
    intr_set_level (old_level);

    /*
    struct thread *cur = thread_current();
    ASSERT(cur != idle_thread);

    enum intr_level old_level;
    old_level = intr_disable();

    cur->wakeup_ticks = time;
    list_insert_ordered(&sleep_list, &cur->elem, sleep_list_less_func, NULL);
    thread_block();
    intr_set_level(old_level);*/

}

void
thread_wakeup (int64_t current_ticks)
{
    next_tick_to_awake = INT64_MAX;
    struct list_elem *e = list_begin(&sleep_list);
    struct thread *t = NULL;
    while (e != list_end(&sleep_list)){
        //&&
            //current_ticks >= (t = list_entry(e, struct thread, elem))->wakeup_ticks){
        struct thread *t = list_entry (e, struct thread, elem);
        if (current_ticks >= t->wakeup_tick)
        {
            // 리스트에서 제거합니다.
            e = list_remove (&t->elem);
            // 스레드 t의 상태를 블록된 상태에서 대기 상태로 변경합니다.
            thread_unblock (t);
        }
        else
        {
            e = list_next (e);
            // 다음 깨우기 틱 갱신
            update_next_tick_to_awake (t->wakeup_tick);
        }
        //e = list_remove(e);
        //thread_unblock(t);
    }
}

void
sort_ready_list(void)
{
    list_sort(&ready_list, ready_list_greater_func, NULL);
}

/*
bool exist_high_priority_than_cur(void)
{
    if(list_empty(&ready_list)) return false;
    return thread_current()->priority
            < list_entry(list_front(&ready_list), struct thread, elem)->priority;
}*/

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle(void *idle_started_ UNUSED) {
    struct semaphore *idle_started = idle_started_;
    idle_thread = thread_current();
    sema_up(idle_started);

    for (;;) {
        /* Let someone else run. */
        intr_disable();
        thread_block();

        /* Re-enable interrupts and wait for the next one.

           The `sti' instruction disables interrupts until the
           completion of the next instruction, so these two
           instructions are executed atomically.  This atomicity is
           important; otherwise, an interrupt could be handled
           between re-enabling interrupts and waiting for the next
           one to occur, wasting as much as one clock tick worth of
           time.

           See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
           7.11.1 "HLT Instruction". */
        asm volatile ("sti; hlt" : : : "memory");
    }
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread(thread_func *function, void *aux) {
    ASSERT (function != NULL);

    intr_enable();       /* The scheduler runs with interrupts off. */
    function(aux);       /* Execute the thread function. */
    thread_exit();       /* If function() returns, kill the thread. */
}

/* Returns the running thread. */
struct thread *
running_thread(void) {
    uint32_t *esp;

    /* Copy the CPU's stack pointer into `esp', and then round that
       down to the start of a page.  Because `struct thread' is
       always at the beginning of a page and the stack pointer is
       somewhere in the middle, this locates the curent thread. */
    asm ("mov %%esp, %0" : "=g" (esp));
    return pg_round_down(esp);
}

/* Returns true if T appears to point to a valid thread. */
static bool
is_thread(struct thread *t) {
    return t != NULL && t->magic == THREAD_MAGIC;
}

/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread(struct thread *t, const char *name, int priority) {
    // DEBUG_PRINT("START\n");
    enum intr_level old_level;
    int i;
    ASSERT (t != NULL);
    ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
    ASSERT (name != NULL);

    memset(t, 0, sizeof *t);
    t->status = THREAD_BLOCKED;
    strlcpy(t->name, name, sizeof t->name);
    t->stack = (uint8_t *) t + PGSIZE;
    t->priority = priority;
    t->original_priority = priority;
    t->base_priority = priority;

    t->magic = THREAD_MAGIC;

    // parant's nice, recent_cpu
    //t->nice = running_thread()->nice;
   // t->recent_cpu = running_thread()->recent_cpu;
    t->nice = 0;
    t->recent_cpu = 0;
    t->working_dir = NULL;

    //list_init(&t->lock_list);
    //t->donating_lock = NULL;

    // old_level = intr_disable();
    list_push_back(&all_list, &t->allelem);

    // 세마포어 초기화
    sema_init (&t->wait_sema, 0);
    sema_init (&t->destroy_sema, 0);
    sema_init (&t->load_sema, 0);

    // 자식 스레드 리스트 초기화
    list_init (&t->child_list);
    // 우선순위 기부 리스트 초기화
    list_init (&t->donations);

    /*
#ifdef USERPROG
    for (i = 0; i < 128; i++) t->fd_table[i] = NULL;
    t->parent = running_thread();
    sema_init(&(t->child_execute_sema), 0);
    t->flag = 0;
    sema_init(&(t->p_sema), 0);
    sema_init(&(t->i_sema), 0);
    list_init(&(t->child_list));
    list_push_back(&(running_thread()->child_list), &(t->i_elem));
#endif*/

    // DEBUG_PRINT("END\n");
    // intr_set_level(old_level);
}

/* Allocates a SIZE-byte frame at the top of thread T's stack and
   returns a pointer to the frame's base. */
static void *
alloc_frame(struct thread *t, size_t size) {
    /* Stack data is always allocated in word-size units. */
    ASSERT (is_thread(t));
    ASSERT (size % sizeof(uint32_t) == 0);

    t->stack -= size;
    return t->stack;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run(void) {
    if (list_empty(&ready_list))
        return idle_thread;
    else
        return list_entry (list_pop_front(&ready_list), struct thread, elem);
}

/* Completes a thread switch by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.  This function is normally invoked by
   thread_schedule() as its final action before returning, but
   the first time a thread is scheduled it is called by
   switch_entry() (see switch.S).

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function.

   After this function and its caller returns, the thread switch
   is complete. */
void
thread_schedule_tail(struct thread *prev) {
    struct thread *cur = running_thread();

    ASSERT (intr_get_level() == INTR_OFF);

    /* Mark us as running. */
    cur->status = THREAD_RUNNING;

    /* Start new time slice. */
    thread_ticks = 0;

#ifdef USERPROG
    /* Activate the new address space. */
    process_activate();
#endif

    /* If the thread we switched from is dying, destroy its struct
       thread.  This must happen late so that thread_exit() doesn't
       pull out the rug under itself.  (We don't free
       initial_thread because its memory was not obtained via
       palloc().) */
    if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread) {
        ASSERT (prev != cur);
        palloc_free_page(prev);
    }
}

/* Schedules a new process.  At entry, interrupts must be off and
   the running process's state must have been changed from
   running to some other state.  This function finds another
   thread to run and switches to it.

   It's not safe to call printf() until thread_schedule_tail()
   has completed. */
static void
schedule(void) {
    struct thread *cur = running_thread();
    struct thread *next = next_thread_to_run();
    struct thread *prev = NULL;

    ASSERT (intr_get_level() == INTR_OFF);
    ASSERT (cur->status != THREAD_RUNNING);
    ASSERT (is_thread(next));

    if (cur != next)
        prev = switch_threads(cur, next);
    thread_schedule_tail(prev);
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid(void) {
    static tid_t next_tid = 1;
    tid_t tid;

    lock_acquire(&tid_lock);
    tid = next_tid++;
    lock_release(&tid_lock);

    return tid;
}

/* Offset of `stack' member within `struct thread'.
   Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof (struct thread, stack);
