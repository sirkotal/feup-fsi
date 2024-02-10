# CTF 8 - RSA

## 1. Reconnaissance

We were given access to a server, available at http://ctf-fsi.fe.up.pt:6004/, and told that the flag would be sent, encrypted with RSA, by the server alongside the modulus and the public exponent (```n``` and ```e```). The first thing we did was to run the ```nc ctf-fsi.fe.up.pt 6004``` command to access the server and retrieve the values of the nonce and the ciphertext in hexadecimal.

![values](images/rsa-ctf/values.png)

## 2. Searching for/Choosing a Vulnerability

After retrieving the values, we started looking for a way to find ```p``` and ```q``` - the prime numbers that generate the ```modulus``` - which were close to 2^512 and 2^513, respectively.

To do that, we were advised to utilize the *Miller-Rabin* algorithm in order to test primality of the primes.

After finding the primes, we then needed to find a way to get ```d```, only knowing that ```d*e % ((p-1)*(q-1)) = 1```.

## 3. Finding an Exploit

We then added the *Miller-Rabin* algorithm and the calculus to find the value of ```d``` to the provided file, which contained funcions to encrypt and decrypt, therefore utilizing the following script.

```python
import random
from binascii import unhexlify
from pwn import *

e = 65537
n =359538626972463181545861038157804946723595395788461314546860162315465351611001926265416954644815072042240227759742786715317579537628833244985694861278970250968348822651571371527626494995987381878217758021702855902005448779458276453536758096804946362851540363648456620089345501998653836930952810277267432387793
ciphertext = "6134636165323466376337323936376335333336623735376665343534393833643135653332306337616662666135396139613630393764383035323933653339653138633466633533376330646632396334313563323364323765383234626336353037303537383337313562656564643935326139616337646132646561383162376163653065316535376664356537306230303838313139613431616165303966363537303062393636333637623366366231626332306534333139623137646531656666393031386536333062386432613566306236393534613334626135666663353962336133393961346666363233353135306538613336316230303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030"

def miller_rabin(n, k):

    # Implementation uses the Miller-Rabin Primality Test
    # The optimal number of rounds for this test is 40
    # See http://stackoverflow.com/questions/6325576/how-many-iterations-of-rabin-miller-should-i-use-for-cryptographic-safe-primes
    # for justification

    # If number is even, it's a composite number

    if n == 2:
        return True

    if n % 2 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True
            
def enc(x, e, n):
    int_x = int.from_bytes(x, "little")
    y = pow(int_x, e, n)
    return hexlify(y.to_bytes(256, 'little'))

def dec(y, d, n):
    int_y = int.from_bytes(unhexlify(y), "little")
    x = pow(int_y,d,n)
    return x.to_bytes(256, 'little')

p = 2**512 + 75 
q = 2**513 + 159

while True:
    if p * q == n:
        break
    elif p * q < n:
        p += 1
        while not miller_rabin(p, 40):
            p += 1
    else:
        p = 2**512 + 75
        q += 1
        while not miller_rabin(q, 40):
            q += 1

d = pow(e, -1, (p-1)*(q-1))

msg = dec(unhexlify(ciphertext), d, n).decode()
print(msg)
```

## 4. Exploring the Vulnerability

When executing it, the program returned the ```cyphertext```given by the server decrypted or, in other words, the required flag.

![flag](images/rsa-ctf/flag.png)
