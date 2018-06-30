#!/usr/bin/python3
'''
Gimme a base 64 encoded <value> you want to decode and a base 64 encoded <key> that was used for the encryption

To get the key run JCEKStractor on {ITIM}/data/keystore/itimKeystore.jceks

yum install python-crypto

'''
import base64,sys
from Crypto.Cipher import AES

def unpad(text, blocklength=16):
    full_len = len(text)
    pad_val = text[-1]
    pos = full_len - pad_val
    if pad_val == 0 or text[-pad_val:] != bytes([pad_val] * pad_val): # if pad_val == 0 or text[-pad_val:] != chr(pad_val) * pad_val:
        raise ValueError('bad padding')
    return text[:pos]

if __name__ == '__main__':
    if len(sys.argv)<3:
        print(__doc__)
        sys.exit(1)
    try:
        encryptkey=base64.b64decode(sys.argv[2])
        password=base64.b64decode(sys.argv[1])
        print(unpad(AES.new(encryptkey, AES.MODE_ECB).decrypt(password)).decode("utf-8"))
    except TypeError:
        print("TypeError: %s on %s\nIs this a valid base64 encoded encryption key?" % (sys.exc_info()[1],sys.argv[3]))
        sys.exit(2)
    except ValueError:
        print("Decoding failed: %s on %s\nWas the data encrypted with a different key?" % (sys.exc_info()[1],sys.argv[1]))
        sys.exit(3)
    except:
        print("Failed: %s on %s" % (sys.exc_info()[1],sys.argv[1]))
