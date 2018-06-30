#!/usr/bin/python3
'''
Gimme a base 64 encoded <value> you want to decode and a <password> for the encryption

the password is either in enRole.properties as enrole.encryption.password or inside encryptionKey.properties as encryption.password
you can get the password from {ITIM}/data/keystore/itimKeystore.jceks using JCEKStractor

'''
import base64,sys
from Crypto.Hash import MD5
from Crypto.Cipher import DES

d_salt = b"\xC7\x73\x21\x8C\x7E\xC8\xEE\x99" # magic

def unpad_pkcs7(text, blocklength=16):
    full_len = len(text)
    pad_val = text[-1]
    pos = full_len - pad_val
    if pad_val == 0 or text[-pad_val:] != bytes([pad_val] * pad_val):
        raise ValueError('bad padding')
    return text[:pos]

def compute_key_iv(password, salt, iterations=20):
    hasher = MD5.new()
    hasher.update(password)
    hasher.update(salt)
    result = hasher.digest()
    for i in range(1, iterations):
        hasher = MD5.new()
        hasher.update(result)
        result = hasher.digest()
    return result[:8], result[8:16]

def decrypt(plain, password, salt, iterations=20):
    key, iv = compute_key_iv(password, salt, iterations)
    decode = DES.new(key, DES.MODE_CBC, iv)
    decrypted = decode.decrypt(plain)
    decrypted = unpad_pkcs7(decrypted)
    return decrypted

if __name__ == '__main__':
    if len(sys.argv)<3:
        print(__doc__)
        sys.exit(1)
try:
    unbase=base64.b64decode(sys.argv[1].encode('utf-8'))
    print(decrypt(unbase,sys.argv[2].encode('utf-8'),d_salt).decode("utf-8"))
except ValueError:
    print("Decoding failed: %s on %s.\nIs this a valid decryption key?" % (sys.exc_info()[1],sys.argv[1]))
except:
    print("Failed: %s on %s." % (sys.exc_info()[1],sys.argv[1]))
