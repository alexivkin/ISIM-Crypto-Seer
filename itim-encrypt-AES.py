#!/usr/bin/python3
'''
Gimme a plain text <value> you want to encode and a base 64 encoded <key> for the encryption

To get the key run JCEKStractor on {ITIM}/data/keystore/itimKeystore.jceks

yum install python-crypto

'''
import base64,sys
from Crypto.Cipher import AES

def pad(s,blocksize): # per standard PKCS#5 is padding to blocksize 8, PKCS#7 is for any block size 1 to 255
    return s + (blocksize - len(s) % blocksize) * chr(blocksize - len(s) % blocksize)

if __name__ == '__main__':
    if len(sys.argv)<3:
        print(__doc__)
        sys.exit(1)
    try:
        encryptkey=base64.b64decode(sys.argv[2])
        padded=pad(sys.argv[1],16)
        encrypted=AES.new(encryptkey, AES.MODE_ECB).encrypt(padded)
        print(base64.b64encode(encrypted).decode('utf-8'))
    except:
        print("Failed: %s on %s" % (sys.exc_info()[1],sys.argv[2]))
