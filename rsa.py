from Crypto.Util import number
import hashlib

# requires pycrypto

def encrypt(ptxt, pk, n):
    return pow(ptxt, pk, n)

def decrypt(ctxt, sk, n):
    return pow(ctxt, sk, n)

def sign(h, sk, n):
    return pow(h, sk, n)

def verify(s, h, pk, n):
    ptxt = pow(s, pk, n)
    if ptxt == h:
        return True
    else:
        return False

def testencrypt(pk, sk, n):
    msg = b"01234567890ABCDEF"
    m = number.bytes_to_long(msg)
    ctxt = encrypt(m, pk, n)
    if sk != None:

        ptxt = decrypt(ctxt, sk, n)
        if ptxt == m:
            return True
        else:
            return False
    return False

def genBasePrimes(psize):
    p = number.getPrime(psize)
    q = number.getPrime(psize)
    while q == p:
        q = number.getPrime(psize)
    return p, q

def keygen(psize):
    good = 0
    # Generate base primes
    p, q = genBasePrimes(psize)
    n = p * q
    t = ((p - 1) * (q - 1))
    # Generate the public key
    pk = (number.getRandomRange(1, t))
    g = number.GCD(pk, t)
    while g != 1:
        pk = (number.getRandomRange(1, t))
        g = number.GCD(pk, t)
        if g == 1:
            break
    # Generate the secret key
    sk = number.inverse(pk, t)
    if pk != None:
        if testencrypt(pk, sk, n):
            good = 1
    return sk, pk, n

def oaep_encrypt(m, mod):
    # This is for testing purposes only
    n = len(bin(abs(mod))[2:]) 
    k0 = 1
    k1 = 0
    ks0 = len(bin(abs(k0))[2:])
    ks1 = len(bin(abs(k1))[2:])
    r = number.getRandomNBitInteger(n)
    G = number.bytes_to_long(hashlib.sha256(number.long_to_bytes(r)).digest())
    X = m ^ G
    H = number.bytes_to_long(hashlib.sha256(number.long_to_bytes(X)).digest())
    Y = r ^ H
    return X, Y

def oaep_decrypt(X, Y):
    r = number.bytes_to_long(hashlib.sha256(X).digest()) ^ number.bytes_to_long(Y)
    m = (number.bytes_to_long(hashlib.sha256(number.long_to_bytes(r)).digest()) ^ number.bytes_to_long(X))
    return m
