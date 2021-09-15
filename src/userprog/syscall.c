#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  // SG_PRJ1 TODO
  /* 
   * You must make syscall_handler() handle system calls`.
   * If you have done argument passing, you can get system call number from intr_frame *f.
   * esp member of intr_frame *f points to system call number.
   * (You can refer to lib/syscall-nr.h to check each system call number)
   * And then you can use switch statement to classify system calls. (What really these system calls do would be written here.)
   * Check argument 'struct intr_frame' of syscall_handler() in syscall.c (struct intr_frame is in src/threads/interrupt.h)
   * */
  printf ("system call!\n");
  thread_exit ();
}

// SG_PRJ1 TODO: Define General System Calls Implementation
// Synchronization will be needed
// (You can use busy waiting)
// exit status is -1 when syscall_handler is terminated in abnormal way
// ...


// SG_PRJ1 TODO: Define fibonacci() and max_of_four_int() system calls
// What really these system calls do would be written here.
// ... fibonacci( ... ) { ... }
// ... max_of_four_int( ... ) { ... }

