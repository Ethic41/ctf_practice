# DigitalOverdose_CTF_2021: ROPuzzle

## Technique: SROP

## Goal: get shell to read flag

### TL;DR

#### observation

```bash
$ checksec main

Arch:     amd64-64-little
RELRO:    No RELRO
Stack:    No canary found
NX:       NX disabled
PIE:      No PIE (0x400000)
RWX:      Has RWX segments

```

- the binary seems to be handcrafted
- it accepts a large user input, enough to perform an srop attack
- we have writable section
- it contains "/bin/sh\x00"
- two obvious gadgets, pop_rax and syscall

#### prerequisite to achieving goal

- to get a shell we need to execute execve('/bin/sh', 0, 0) syscall
- to make the syscall we have to find a way to set RAX register to the syscall number(0x3b)

#### solving

- it doesn't seem like we can do normal ROP (but maybe you can)
- we will use SROP attack
- we create a small rop chain to set RAX to 0xf (syscall number for sigreturn) and return to syscall
- since we have "/bin/sh\x00" in memory no need to write
- append execve sigreturn frame to the end of the chain
- make syscall, get a shell and cat flag.txt

#### full writeup

- [https://maplebacon.org/2022/04/tamuctf-void/](https://maplebacon.org/2022/04/tamuctf-void/)
