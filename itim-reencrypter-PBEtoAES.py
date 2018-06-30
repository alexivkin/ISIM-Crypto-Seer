#!/usr/bin/python3
'''
Convert PBEWithMD5AndDES to AES/ECB/PKCS5Padding (Oracle JDK 6 and 7 use AES/ECB/PKCS5Padding when only AES is specified)

Gimme a base 64 encoded value you want to <decode>, a <password> for the decryption an a base64 encoded <key> for encryption

For ISIM the encryption/decryption password is either in enRole.properties as enrole.encryption.password or inside encryptionKey.properties as encryption.password
The you can get the password from {ITIM}/data/keystore/itimKeystore.jceks using JCEKStractor

yum install python-crypto

'''
import base64,sys
from Crypto.Hash import MD5,SHA256
from Crypto.Cipher import DES,AES

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
d_salt = "\xC7\x73\x21\x8C\x7E\xC8\xEE\x99" # magic

def unpad_pkcs7(text, blocklength=16):
    full_len = len(text)
    pad_val = text[-1]
    pos = full_len - pad_val
    if pad_val == 0 or text[-pad_val:] != bytes([pad_val] * pad_val): # python2 is ok with if pad_val == 0 or text[-pad_val:] != chr(pad_val) * pad_val:
        raise ValueError('bad padding')
    return text[:pos]

def compute_key_iv(password, salt, iterations=20):
    hasher = MD5.new()
    hasher.update(password)
    hasher.update(salt)
    result = hasher.digest()
    for i in xrange(1, iterations):
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

def encrypt(message, key):
    raw = pad(message)
    encoder = AES.new(key, AES.MODE_ECB)
    return encoder.encrypt(raw)

if __name__ == '__main__':
    if len(sys.argv)<4:
        print (__doc__)
        sys.exit(1)
    try:
        decoded=decrypt(base64.b64decode(sys.argv[1]),sys.argv[2],d_salt)
        print(decoded)
        print(base64.b64encode(encrypt(decoded, base64.b64decode(sys.argv[3]))))
    except ValueError:
        print("Decoding failed: %s on %s.\nIs this a valid  key?" % (sys.exc_info()[1],sys.argv[2]))
    except:
        print("Failed: %s on %s.\nIs this a valid base64 encoded encryption key?" % (sys.exc_info()[1],sys.argv[3]))
