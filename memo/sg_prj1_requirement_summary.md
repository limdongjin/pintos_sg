## 1

1. Process Termination Messages
2. Argument Passing 
  - parse argument."cat hello world" => "cat", "hello", "world" 
  - allocate it to memory according to 80x86 calling convention (pintos man 3.5)
  - Assume that the length of arguments is less than 4 KB
3. System Calls / handler / additional
  - refer to pintos man 3.3.4
  - syscall_handler
  - syscall impl : halt, exit, exec, wait, read(stdin), write(stdout)
    - Synchronization will be needed
    - (You can use busy waiting)
    - exit status is -1 when syscall_handler is terminated in abnormal way
  - implement two additional system calls : fibonacci, max_of_four_int
    - modify src/lib/syscall-nr.h src/lib/syscall.h src/lib/syscall.c
    - make src/examples/additional.c ...
4. User Memory Access
  - invalid pointers must be rejected
  - Make a plan for protecting user memory accesses from system calls
  - Recommend to implement the function which checks the validity of given address
  - refer to pintos man 3.1.5
  - refer to src/threads/vaddr.h


## Suggested Order of implementation

arg passing
user memory access
syscall handler
syscall impl
additional syscall

