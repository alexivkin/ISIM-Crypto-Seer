#!/usr/bin/python3
""" ITIM/IGI Adapter decrypter

Decrypts IBM published adapter zipped files that are encrypted and have .enc ending
needs pycrypto

pip install pycrypto - it's in c and will need build toolchain to compile (aka gcc, make, autoconf)

2015 (c) Alex Ivkin v1.0
"""
from __future__ import with_statement
import re,sys
from Crypto.Cipher import DES

if len(sys.argv)==1:
    print(__doc__)
    sys.exit(1)

key = b'\x16\x0E\xFA\x22\x01\x89\xDE\x36' # magic, pure magic
# DES/CBC/PKCS5Padding, iv is the key
cipher=DES.new(key, DES.MODE_CBC, key)
fn_in=sys.argv[1]
# remove .enc extension if present, otherwise add a .dec extension
fn_out=re.sub(r'\.enc$','',fn_in)
if fn_out == fn_in:
    fn_out = fn_in+'.dec'
print("Decoding "+fn_in+" to "+fn_out+"...")
bs = DES.block_size
next_chunk = b''
finished = False

with open(fn_in, 'rb') as in_file, open(fn_out, 'wb') as out_file:
    while not finished:
        chunk, next_chunk = next_chunk, bytes(cipher.decrypt(in_file.read(1024 * bs)))
        if len(next_chunk) == 0:
            padding_length = chunk[-1]
            chunk = chunk[:-padding_length]
            finished = True
        out_file.write(chunk)
