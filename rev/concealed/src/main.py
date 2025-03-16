#!/usr/bin/env python3
import sys, os
from cryptography.fernet import Fernet

def generate_key(password):
    if password == "n3wP@ssw0rd123":
        return b"i+P0ibYpb1s8yUa59N4mFsY+RR/qWNA11AXsIe5OcdE="
    return ""

with open(sys.argv[0], "rb") as f:
    f.seek(1693)
    with open("lib.pyc", "wb") as ff:
        ff.write(f.read())
    import lib
    generate_key = lib.hidden_func
    os.remove("lib.pyc")

def unlock_secret(password):
    key = generate_key(password)
    if key:
        return "Spectacular! You cracked the code.\n" + Fernet(key).decrypt(b"gAAAAABnwGsbt_T6av7yIIKiIM4Zxyb400IieMQsULzzv9qiPKcBiT3i04X3jgAPGvRJD34Upj5cc7gCqb4e3mS4wqCvcfo3b06S0wQRvO4oFzHmn3a_v6J0QmwXmqkaGlg8FaHUWOwF").decode()
    return "Not Quite. Try again!"

print(unlock_secret(input("The lock was broken. Can you find the correct key?\n")))
