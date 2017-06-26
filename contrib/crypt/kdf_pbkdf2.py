#!/usr/bin/env python3

import sys
import os
import getpass
import hashlib

def passprompt():
    pprompt = lambda: (getpass.getpass("Passphrase: "), getpass.getpass("Retype passphrase: "))
    p1, p2 = pprompt()
    while p1 != p2:
        print("No match, please try again")
        p1, p2 = pprompt()
    return p1

if len(sys.argv) <= 1:
    print("Usage: {} <dklen>".format(sys.argv[0]), file=sys.stderr)
    sys.exit(1)

hash_name = "sha256"
iterations = 300000
dklen = int(sys.argv[1])
salt = os.urandom(16)
password = passprompt().encode("utf-8")

dk = hashlib.pbkdf2_hmac(hash_name=hash_name, password=password, salt=salt, iterations=iterations, dklen=dklen)

salt_hex = "".join(["{:02x}".format(x) for x in salt])
dk_hex = "".join(["{:02x}".format(x) for x in dk])

print("KEY=" + dk_hex);
print("algoritm=pbkdf2_hmac");
print("hash_name=" + hash_name);
print("salt=" + salt_hex);
print("iterations=" + str(iterations));
