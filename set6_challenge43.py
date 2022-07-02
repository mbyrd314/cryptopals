from cryptography.hazmat.primitives import hashes
import random

class DSA():
    def __init__(self, p, q, g):
        self.p = p
        self.q = q
        self.g = g
        self.H = hashes.Hash(hashes.SHA1())
        self.N = 160
        self.L = 1024
        self.h = 2 # Guessing this is what they used. Might have to change it
        self.keys = dict()

    def recv_pubkey(self, id, pubkey):
        self.keys[id] = pubkey

    def verify(self, id, m, r, s):
        print(f'Verifying {m}')
        y = self.keys[id]
        if r < 1 or r >= self.q or s < 1 or s >= self.q:
            return False
        m_bytes = m.to_bytes(32, byteorder='big')
        w = extended_gcd(s, self.q)
        wprod = (w*s)%self.q
        print(f'wprod={wprod}')
        w2 = pow(s, -1, self.q)
        print(f'w={w}')
        print(f'w2={w2}')
        w2prod = (s*w2)%self.q
        self.H.update(m_bytes)
        Hm = int.from_bytes(self.H.finalize(), byteorder='big')
        u1 = (Hm*w)%self.q
        u2 = (r*w)%self.q
        gu = pow(self.g, u1)
        yu = pow(y, u2)
        v = ((gu * yu)%self.p)%self.q
        # v = ((pow(self.g, u1, self.p)*pow(y, u2, self.p))%self.p)%self.q
        print(f'Hm={Hm}')
        print(f'v={v}')
        print(f'r={r}')
        return v == r

def extended_gcd(a, b):
    """
    Implementation of the extended GCD algorithm to determine modular multiplicative
    inverse of a mod b
    """
    # print(f'a={a}, b={b}')
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r:
        quotient = old_r // r
        old_r, r = r, old_r - quotient*r
        old_s, s = s, old_s - quotient*s
        old_t, t = t, old_t - quotient*t
        # print(f'quotient={quotient}, old_r={old_r}, r={r}, old_s={old_s}, s={s}, old_t={old_t}, t={t}')
    if old_s < 0:
        old_s += b
    return old_s


if __name__ == '__main__':
    p = b'800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1'
    q = b'f4f47f05794b256174bba6e9b396a7707e563c5b'
    g = b'5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291'
    print(f'len(p)={len(p)}, len(q)={len(q)}, len(g)={len(g)}')
    pn = int.from_bytes(p, byteorder='big')
    qn = int.from_bytes(q, byteorder='big')
    gn = int.from_bytes(g, byteorder='big')
    x = random.randint(1, qn-1)
    y = pow(gn, x, pn)
    dsa = DSA(pn, qn, gn)
    dsa.recv_pubkey(0, y)
    m = random.randint(1, 2**256-1) # Generate a random 256 bit message
    r = s = 0
    while r == 0 or s == 0:
        k = qn
        while qn % k == 0:
            k = random.randint(1, qn-1)
            print(f'Generated k = {k}')
            print(f'qn/k={qn/k}')
        print('Finished k')
        r = (pow(gn, k, pn))%qn
        kinv = extended_gcd(k, qn)
        kinv2 = pow(k, -1, qn)
        kprod2 = (k*kinv2)%qn
        m_bytes = m.to_bytes(32, byteorder='big')
        H = hashes.Hash(hashes.SHA1())
        H.update(m_bytes)
        Hm = int.from_bytes(H.finalize(), byteorder='big')
        s = (kinv*(Hm+x*r))%qn
        kprod = (k*kinv) % qn
        print(f'Signing {m}')
        print(f'k={k}')
        print(f'kprod={kprod}')
        print(f'kinv={kinv}')
        print(f'kinv2={kinv2}')
        print(f'kprod2={kprod2}')
        print(f'r={r}')
        print(f's={s}')
        print(f'Hm={Hm}')
        print()
    valid = dsa.verify(0, m, r, s)
    if valid:
        print(f'Random message successfully signed and verified')
    else:
        print(f'Some error in signing and verifying message')
