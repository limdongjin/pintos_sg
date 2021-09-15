# alias  

## write to ~/.bashrc
1. pintos-prj1-prepare
alias pintos-prj1-prepare="rm filesys.dsk && pintos-mkdisk filesys.dsk --filesys-size=2 && pintos -f -q && pintos -p ../../examples/echo -a  echo -- -q"

2. pintos-gdb-echo
alias pintos-gdb-echo="pintos --gdb -- -q run 'echo hello world'"

3. pintos-echo
alias pintos-echo="pintos -q run 'echo hello world'"