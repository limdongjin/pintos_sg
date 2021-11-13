#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "lib/user/syscall.h"
#include <stdlib.h>
#include <stdio.h>
void syscall_init (void);

// SG_PRJ1 TODO_DONE: write prototype of general system calls
#define SYSCALL_MAX_ARGC 10
#define ABNORMAL_EXIT_CODE (-1)

void halt (void);
void exit (int status);
pid_t exec (const char *cmd_line);
int wait (pid_t pid);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void abnormal_exit(void);

void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);

/* Project 3 and optionally project 4. */
mapid_t mmap (int fd, void *addr);
void munmap (mapid_t);

/* Project 4 only. */
bool chdir (const char *dir);
bool mkdir (const char *dir);
bool readdir (int fd, char name[READDIR_MAX_LEN + 1]);
bool isdir (int fd);
int inumber (int fd);

// SG_PRJ1 TODO_DONE: write prototype of 2 new system call APIs
int fibonacci(int n);
int max_of_four_int(int a, int b, int c, int d);
bool check_user_ptr(const void *user_ptr, void *esp);
bool is_valid_stack(int32_t addr, int32_t esp);
struct lock file_lock;

#endif /* userprog/syscall.h */
