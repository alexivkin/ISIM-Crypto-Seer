#!/usr/bin/python3
'''
Unobfuscate the master password from the obfuscated encryptionKey.properties file.

yum install python-crypto

'''
import base64,sys,traceback
from Crypto.Hash import MD5
from Crypto.Cipher import DES,AES

pad = b'\xc7\xc7\xc7\xc7\xc7\xc7\xc7\xc7\x99\x99\x99\x99\x99\x99\x99\x99'
des_salt = b'\xc7\x73\x21\x8c\x7e\xc8\xee\x99'
des_iter = 20
des_pass = "sec#:(){:|:&};:ret8474sunshine"

def compute_key_iv(password, salt, iterations):
    hasher = MD5.new()
    hasher.update(password)
    hasher.update(salt)
    result = hasher.digest()
    for i in range(1, iterations):
        hasher = MD5.new()
        hasher.update(result)
        result = hasher.digest()
    return result[:8], result[8:16]

def decryptPBEWithMD5AndDES(plain, password, salt, iterations):
    key, iv = compute_key_iv(password, salt, iterations)
    decode = DES.new(key, DES.MODE_CBC, iv)
    decrypted = decode.decrypt(plain)
    decrypted = unpad(decrypted)
    return decrypted


def unpad(text, blocklength=16):
    full_len = len(text)
    pad_val = text[-1]
    #print("%s" % pad_val)
    pos = full_len - pad_val
    if pad_val == 0 or text[-pad_val:] != bytes([pad_val] * pad_val):
        raise ValueError('bad padding')
    return text[:pos]


if len(sys.argv)<2:
    print(__doc__)
    sys.exit(1)

with open(sys.argv[1],"rb") as kf:
    # check the sig
    kf.seek(-16,2)
    sig=kf.read(16)
    if sig != pad:
        print("Invalid file. It should start with %s\n" %pad)
        sys.exit(2)
    kf.seek(0)
    data=kf.read()[:-16] # ingest and trim
    #dd=open("xx","wb")
    #dd.write(data)
    try:
        undes=decryptPBEWithMD5AndDES(data,des_pass.encode('utf-8'),des_salt,des_iter)
        plain=unpad(AES.new(undes[-16:], AES.MODE_ECB).decrypt(undes[:-16]))
        print(plain.decode('utf-8'))
    except TypeError:
        print("TypeError: %s on %s\n" % (sys.exc_info()[1],sys.argv[1]))
        traceback.print_exc()
        sys.exit(2)
    except ValueError:
        print("Decoding failed: %s on %s\n" % (sys.exc_info()[1],sys.argv[1]))
        traceback.print_exc()
        sys.exit(3)
    except:
        print("Failed: %s on %s" % (sys.exc_info()[1],sys.argv[1]))
        traceback.print_exc()
