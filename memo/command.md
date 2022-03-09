# 핀토스 관련 커맨드 

0. 테스트 실행전 사전작업
0.1. utils 폴더로 들어가서 make
0.2 threads 폴더로 들어가서 make
0.3 userprog ........... make

1. make check : 모든 테스트 스레드 한번에 검증
  - src/threads//build 에서 실행 

2. pintos -q run <test-name> : 원하는 스레드만 검증 
  - src/threads/build 에서 실행
  - "-q" 옵션은 실행이 끝나면 해당 task를 kill 하겠다는 의미임. 
  - <test-name> 에는 alarm-multiple, priority-sema, priority-donate-one 중에 하나를 선택가능함.

3. pintos --gdb -- run alarm-multiple

// in userprog/build
4. pintos-mkdisk filesys.dsk --filesys-size=2

// in userprog/build
5. pintos -f -q

// in userprog/build
6. pintos -p ../../examples/echo -a  echo -- -q

// 7 = 4 + 5 + 6 
7. pintos --filesys-size=2 -p ../examples/echo -a echo -- -f -q run 'echo x'

// but if you want debugging,
9. cd userprog/build
10. pintos-mkdisk filesys.dsk --filesys-size=2
11. pintos -f -q
12. pintos -p ../../examples/echo -a  echo -- -q
13. cd .. #move to userprog/
14. pintos --gdb -- -q run 'echo hello world'

// but if you wand quick debugging.
15. alias pintos-prj1-prepare, pintos-gdb-echo memo/alias.md
16. just run two command.

# For Fintos..
export PATH="$PATH:/home/imdongjin/pintos/src/utils"
export PATH="$PATH:/home/imdongjin/CLionProjects/pintos_sg/src/utils"
alias gobuild="cd /home/imdongjin/pintos/src/threads/build"
alias gohomep="cd /home/imdongjin/pintos"
export PATH="$PATH:/usr/local/bin"

alias pintos-prj1-prepare="rm -f filesys.dsk && pintos-mkdisk filesys.dsk --filesys-size=2 && pintos -f -q && pintos -p ../../examples/echo -a  echo -- -q"

alias pintos-prj2-prepare="rm -f filesys.dsk && pintos-mkdisk filesys.dsk --filesys-size=2 && pintos -f -q && pintos -p tests/userprog/read-normal -a  read-normal -- -q && pintos -p ../../tests/userprog/sample.txt -a sample.txt -- -q"
alias pintos-prj2-gdb-go="pintos-prj2-prepare && pintos --gdb -- -q -f extract run read-normal"

alias pintos-gdb-echo="pintos --gdb -- -q run 'echo x'"
alias pintos-echo="pintos -q run 'echo xhello world good go  go'"
alias pintos-1-go="pintos-prj1-prepare && pintos-echo"
alias pintos-1-go-gdb="pintos-prj1-prepare && pintos --gdb -- -q run 'echo hello world good'"
