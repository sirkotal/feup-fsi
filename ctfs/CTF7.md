# CTF 7 - Weak Encryption

## 1. Reconnaissance

We were given access to a server, available at http://ctf-fsi.fe.up.pt:5003/, that sent a flag encrypted using AES-CTR (AES in Counter mode).
A Python file named *cipherspec.py* was also given to us, containing the key generation, encryption and decryption algorithms.

The first thing we did was to run the ```nc ctf-fsi.fe.up.pt 6003``` command to access the server and retrieve the values of the nonce and the ciphertext in hexadecimal.

![hex-values](images/weak-encryption-ctf/hex_values.png)

## 2. Searching for/Choosing a Vulnerability

After retrieving the values, we decided to take a look at the code provided in the *cipherspec.py* file:

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

KEYLEN = 16

def gen(): 
	offset = 3 # Hotfix to make Crypto blazing fast!!
	key = bytearray(b'\x00'*(KEYLEN-offset)) 
	key.extend(os.urandom(offset))
	return bytes(key)

def enc(k, m, nonce):
	cipher = Cipher(algorithms.AES(k), modes.CTR(nonce))
	encryptor = cipher.encryptor()
	cph = b""
	cph += encryptor.update(m)
	cph += encryptor.finalize()
	return cph

def dec(k, c, nonce):
	cipher = Cipher(algorithms.AES(k), modes.CTR(nonce))
	decryptor = cipher.decryptor()
	msg = b""
	msg += decryptor.update(c)
	msg += decryptor.finalize()
	return msg
```

By analyzing the code, it was clear that we were dealing with a 128-bit key (16 bytes long), which by itself should be secure and able to endure any brute-force attacks.

The ```gen``` function generates a 128-bit key in byte code.
Meanwhile, the ```enc``` function is responsible for encrypting a message ```m``` using the AES-CTR algorithm with a given key ```k``` and nonce ```nonce```. It firstly initializes an AES cipher (in Counter mode), creates an encryptor based on the chosen cipher and encrypts the message using it; it then returns the resulting ciphertext.
The ```dec``` function does the exact opposite of ```enc``` - it decrypts the ciphertext using the AES-CTR algorithm.


The issue in this code, however, seemed to come not from the encryption process itself but from the fact that the first 13 bytes of the key were actually static - ```key = bytearray(b'\x00'*(KEYLEN-offset))```.

This meant that only the last 3 bytes were effectively randomized - ```key.extend(os.urandom(offset))``` - since the first 13 bytes simply had the value of ```\x00```. For this reason, the 128-bit key was actually just a 24-bit key, which made it much easier to crack using a brute-force attack.

## 3. Finding an Exploit

Knowing that the first 13 bytes of the key were static, we decided to target its last 3 bytes by devising a brute-force attack capable of compromising the encryption.

To do this, we created a loop that iterated through all the possible values of the key, taking into account that only the final 3 bytes were not zeros.
Then, for each possible value of the key, we decrypted it and checked if the byte sequence ```flag``` (since we knew the format of the flag, and therefore, of the message) was present in the decrypted message. If the sequence was present in the decrypted message, we had found the key; otherwise, the program would keep searching for the correct value of the last 3 bytes until the condition was met.

```py
nonce_hex = "a4dce04829c1ffc9033b7b094826b73f"
ciphertext_hex = "4eae729af90af365fc217f0aff561beafd9bb0981fae086c065dbed9eb7a2a99a4bd9dbf858f2f"

def brute_force_decrypt(nonce, ciphertext):
    offset = 3
    for i in range(256**offset):
        key = i.to_bytes(16, 'big')
        decrypted = dec(key, ciphertext, nonce)
        if b'flag' in decrypted:
            print(f"Key found: {key}")
            print(f"Decrypted message: {decrypted.decode('utf-8')}")
            return True
        print("Aperture Science Portal Check") # LOOPS!
    return False

nonce = unhexlify(nonce_hex)
ciphertext = unhexlify(ciphertext_hex)

brute_force_decrypt(nonce, ciphertext)
```

This approach was feasible due to the fact that the key space was reduced to "just" 16777216 possibilities - (2^8)^3, which represents the number of possible values (2^8) for each of the 3 randomized bytes.

## 4. Exploring the Vulnerability

Having developed an exploit, we went ahead and executed it; after waiting some time, the program returned the original value of the key and the decrypted message, containing the flag.

![flag](images/weak-encryption-ctf/flag.png)