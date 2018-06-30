# IBM Security Identity Manager encryption and decryption tools

If you ever needed to recover encrypted ISIM passwords or re-encrypt them with a different key, this is the set of tools you need.

As a bonus you have a tool for decrypting the ISIM adapter distributions (in case you don't want to waste time with the IBM installer to get to the TDI source code of the adapter).

The tools are all very ITIM specific - the algorithms, the salt, number of rounds. Do not expect them to work on any other IBM software.

## Tools
For python tools you need Python 3 and python-crypto package (PyCrypto). You can install that package with `apt install python-crypto`, `yum` or `pip install pycrypto`
For Java you need JRE 1.6+ and the jar libs from IBM or this repo.

### Decrypt SIM 6 passwords - itim-decrypt-AES.py
Decrypt a password stored in the AES scheme. To run provide a base 64 encoded <value> you want to decode and a base 64 encoded <key> used for the encryption.

If you do not remember the encryption key look it up in enRole.properties enrole.encryption.password. If it's commented out, the key is in itimKeystore.jceks.
To recover it you will need to run `itim_JCEKStractor.java` from this repo. You might also need to run `itim-decrypt-encryptionKey.py` (see below).

### Decrypt TIM 5 passwords - itim-decrypt-PBEWithMD5AndDES.py
Decrypt a password stored in the old and weak DES/CBS/MD5 scheme. You will need to provide a base64 encoded value and a password that was used for the encyption. If you do not remember the encryption password you can recover it with the JCEKS extractor and encryptionKey decrypter.

### Decrypt TIM 4.5.1 and TIM 4.6 passwords - itim_decrypt_PBEWithSHAAnd128BitRC2.java
Decrypt a password stored with old and obsolete PBE/SHA1/RC2/CBC/PKCS12PBE-5-128 scheme. It the weakened "exportable" pre-2000 encryption. It uses an external crypto library because of a completely butchered up, out-of-spec implementation of the PBE in the old ITIM. Compile with
```
javac -XDignore.symbol.file -cp jsafe.jar itim_decrypt_PBEWithSHAAnd128BitRC2.java
```
Run with
```
java -cp .:jsafe.jar itim_decrypt_PBEWithSHAAnd128BitRC2 [base64 encoded text] [encryption password]
```
or on Windows with
```
java -cp .;jsafe.jar itim_decrypt_PBEWithSHAAnd128BitRC2 [base64 encoded text] [encryption password]
```
(the -cp (classpath) argument uses the current folder which is dot colon on Linux or dot semicolon on Windows)

### Extract binary encryption password - itim_JCEKStractor.java
Why do you need this? Well, at some point in ITIM's evolution the encryption key that is specified during the install stopped being used directly for encryption of sensitive attributes. Instead the ITIM installer creates a random password that is then for the encryption of the attributes. That password is stashed into a JCEKS (Java Cryptography Extension Key Store) file. Finally that file is closed off with the encryption password that you specified during the install.

Oddly no standard tool exists that can assist in extracting that 'secure' random password. So I wrote my own.

To extract the random encryption password you will need to specify the location of your itimKeystore.jceks and the password that was used to create it. If you do not remember the password that was used to create it, look in enRole.properties for enrole.encryption.password. If it is commented out you will need to use `itim-decrypt-encryptionKey.py`

Compile with
```
javac itim_JCEKStractor.java
```
Run with
```
java itim_JCEKStractor itimKeystore.jceks jceks-access-password
```

If you see "com.ibm.crypto.provider.AESSecretKey" as the result, then you need to install `ibmjceprovider.jar` or run it on a JVM with the IBM Crypto provider installed (e.g WAS JVM - /opt/IBM/WebSphere/AppServer/java/bin/java )
To enable the provider, add security provider to your java.security:
```
echo "security.provider.10=com.ibm.crypto.provider.IBMJCE" | sudo tee -a $(dirname "$(readlink -f $(which java))")/../lib/security/java.security
```
and copy ibmjceprovider.jar to your classpath
```
sudo cp ibmjceprovider.jar $(dirname "$(readlink -f $(which java))")/../lib/ext/
```

More info on [Installing IBM Crypto Providers](https://www.ibm.com/support/knowledgecenter/en/SSYKE2_7.0.0/com.ibm.java.security.component.70.doc/security-component/JceDocs/installingproviders.html).
The ibmjceprovider.jar lib is distributed with the [IBM JDK](https://www.ibm.com/developerworks/java/jdk/java8/) inside lib/ext/


### Unobfuscate encryption key - itim-decrypt-encryptionKey.py
Why this? Ok, before some fixpack ITIM used to store the encryption key in plain text in encryptionKey.properties. Thenm, as another layer of pseudo-security ITIM started obfuscating encryptionKey.properties file to hide the encryption.password.

First look at the encryptionKey.properties file. If it opens and you can see encryption.password, then you do not need this tool. Just use it directly with itim_JCEKStractor.
However, if the file looks like binary garbage, then feed it to this script. It will de-obfuscate it and print it for you all nice and pretty.

### Decrypt adapter distribution - itim-decode-adapter.py
Again, some obfuscation that gets in the way of doing stuff, while not providing much security. If you download an ISIM adapter and see a file that ends with .enc, this tool allows you to
decode/decrypt/deobfuscate the adapter file and recover the actual .zip. Just run it with the name of the archive, and it'll give you the original

### Encrypt a password - itim-encrypt-AES.py
This is a reverse of the "decrypt AES" script. Use it on a plain text password and a base 64 encoded key for the encryption

### Decrypt and reencrypt a password - itim-reencrypter-PBEtoAES.py
Just a simple automation script to convert a password from PBEWithMD5AndDES to AES/ECB/PKCS5Padding. Run it with a base 64 encoded value you want to decode, a password for the decryption, and a base64 encoded key for encryption.

If you need more automation, like reencrypting the whole ldap, look at `reencrypter` in my ISIM Ldap Sifter repo.

## Questions
### How do I just get a password decrypted for TIM 6?
Try this:
```
itim-decrypt-encryptionKey.py <itim>/data/encryptionKey.properties
WebSphere/AppServer/java/bin/java itim_JCEKStractor /opt/IBM/isim/data/keystore/itimKeystore.jceks <key you just extracted>
itim-decrypt-AES.py [base64 encoded password from LDAP] <base64 key from jceks>
```

### How do I know what encryption scheme is the right one to pick?
General rule - for TIM 5.1 you're on 'PBEWithMD5AndDES', for SIM 6 and above you have AES, for TIM 4.5.1 or 4.6 use PBE-SHA1-RC2. For specifics look at your enRole.properties: enrole.encryption.algorithm
Depending on how TIM was upgraded it's crypto algorithm may stay the same as the original one.

AES is actually AES/ECB/PKCS5Padding since JDK 6 and 7 will use that cipher suite when only AES is specified.


### What is my encryption key?
Look at enRole.properties: enrole.encryption.password. If it's commented out and enrole.encryption.password.encoded is true, then your encryption key is inside encryptionKey.properties. However it was not used directly to encrypt sensitive attributes, but rather to create itimKeystore.jceks. That jceks stores a random key that is actually used to encrypt sensitive attributes.

### Where is my itimKeystore.jceks?
Usually under {ITIM}/data/keystore/. Otherwise look at enRole.properties: enrole.encryption.keystore

### How can I use it on all LDAP passwords?
Look at my ISIM Ldap Sifter repo

## Thanks
You can say thanks here - http://ivkin.net