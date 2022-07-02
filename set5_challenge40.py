import random
from sympy import cbrt

def generate_prime(n):
    """
    Generates an n-bit prime number
    """
    while True:
        num = random.randint(2**(n-1), 2**n-1)
        # print(f'Generated num: {num}')
        if is_prime(num):
            return num
def is_prime(num):
    low_primes = [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97]
    for p in low_primes:
        if num == p:
            return True
        elif num % p == 0:
            # print(f'Num {num} is divisible by {p}')
            return False
    return rabin_miller(num)

def rabin_miller(n, k=11):
    """
    Implementation of the Rabin-Miller primality test
    """
    d = n-1
    s = 0
    while d % 2 != 0:
        d //= 2
        s += 1
    # print(f'Rabin-Miller: n={n}, k={k}, d={d}, s={s}')
    for _ in range(k):
        a = random.randint(2, n-2)
        x = pow(a, d, n)
        if x == 1 or x == n-1:
            continue
        else:
            for _ in range(s-1):
                x = pow(x, 2, n)
                if x == n-1:
                    continue
        return False
    return True

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

def gcd(a, b):
    while b:
        a, b = b, a%b
    return a

def lcm(a, b):
    return (a*b)//gcd(a, b)

class RSA:
    def __init__(self, size=64):
        self.p = generate_prime(size)
        self.q = generate_prime(size)
        self.n = self.p * self.q
        self.et = lcm(self.p-1,self.q-1)
        # self.et = (self.p-1) * (self.q-1)
        self.e = 3
        self.d = extended_gcd(self.e, self.et)
        print(f'size={size}, p={self.p}, q={self.q}, n={self.n}, et={self.et}, e={self.e}, d={self.d}')


    def encrypt(self, m):
        return pow(m, self.e, self.n)

    def decrypt(self, c):
        return pow(c, self.d, self.n)

    def get_pubkey(self):
        return self.n

if __name__ == '__main__':
    plaintext = int.from_bytes(b'Test message', byteorder='big')
    print(f'plaintext={plaintext}')
    rsa0 = RSA(128)
    c0 = rsa0.encrypt(plaintext)
    n0 = rsa0.get_pubkey()
    rsa1 = RSA(128)
    c1 = rsa1.encrypt(plaintext)
    n1 = rsa1.get_pubkey()
    rsa2 = RSA(128)
    c2 = rsa2.encrypt(plaintext)
    n2 = rsa2.get_pubkey()
    ms0 = n1 * n2
    ms1 = n0 * n2
    ms2 = n0 * n1
    n012 = n0 * n1 * n2
    print(f'n0={n0}')
    print(f'n1={n1}')
    print(f'n2={n2}')
    print(f'n012={n012}')
    print(f'ms0={ms0}')
    print(f'ms1={ms1}')
    print(f'ms2={ms2}')
    result = (c0 * ms0 * extended_gcd(ms0, n0)) % n012
    result = (result + c1 * ms1 * extended_gcd(ms1, n1)) % n012
    result = (result + c2 * ms2 * extended_gcd(ms2, n2)) % n012
    # root = pow(result, 1./3)
    root = cbrt(result)
    print(f'result={result}')
    print(f'root={root}')
    print(f' msg={plaintext}')
    print(f'root==msg={root==plaintext}')
