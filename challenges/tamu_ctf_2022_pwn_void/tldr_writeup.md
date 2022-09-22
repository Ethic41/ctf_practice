# TAMU_CTF_2022: VOID

## Technique: SROP

## Goal: get shell to read flag

### TL;DR

#### observation

- the binary seems to be handcrafted
- it accepts a large user input, enough to perform an srop attack

#### prerequisite to achieving goal

- to get a shell we need to execute execve('/bin/sh', 0, 0) syscall
- to make the syscall we have to find a way to set RAX register to the syscall number(0x3b)
- we also need to write "/bin/sh\x00" somewhere in memory
- and then we have to set RDI to that (value of bin_sh) memory address
- then we make the syscall

#### solving

- we are using an srop attack
- we have a syscall gadget at 0x401018
- we can use the read syscall to read *n* bytes and control the value of rax, where n is the syscall number
- create a SigReturn (sigret) frame to perform an ***mprotect*** syscall to get a writable section ([mprotect(0x402000, 0x1000, 7)]), such that writable section becomes our new fake stack
- make syscall
- create another sigret frame to perform ***execve*** syscall ([execve('/bin/sh\x00', 0, 0)])
- append '/bin/sh\x00' to the end of the sigret frame bytes to write it on our fake stack
- make syscall, get a shell and cat flag.txt
