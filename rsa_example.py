from rsa import keygen, encrypt, decrypt, sign, verify
from Crypto.Util import number

psize = 128
skA, pkA, nA = keygen(psize)
skB, pkB, nB = keygen(psize)
msg = 65
ctxt = encrypt(msg, pkB, nB)
print(ctxt)
ptxt = decrypt(ctxt, skB, nB)
print(ptxt)

s = sign(ctxt, skA, nA)
v = verify(s, ctxt, pkA, nA)
print(v) 
