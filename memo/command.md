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