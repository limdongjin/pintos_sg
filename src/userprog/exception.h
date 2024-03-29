#ifndef USERPROG_EXCEPTION_H
#define USERPROG_EXCEPTION_H

/* Page fault error code bits that describe the cause of the exception.  */
#define PF_P 0x1    /* 0: not-present page. 1: access rights violation. */
#define PF_W 0x2    /* 0: read, 1: write. */
#define PF_U 0x4    /* 0: kernel, 1: user process. */

#include <stdint.h>
#include <stdbool.h>
// 8MB
#define STACK_SIZE_LIMIT (8*1024*1024)

void exception_init (void);
void exception_print_stats (void);
bool verify_stack (int32_t addr, int32_t esp);
#endif /* userprog/exception.h */
