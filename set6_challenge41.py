# Unpadded Message Recovery Oracle
import random

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
        self.e = 65537
        self.d = extended_gcd(self.e, self.et)
        print(f'size={size}, p={self.p}, q={self.q}, n={self.n}, et={self.et}, e={self.e}, d={self.d}')

    def get_modulus(self):
        return self.n

    def get_pub_exp(self):
        return self.e

    def encrypt(self, m):
        return pow(m, self.e, self.n)

    def decrypt(self, c):
        return pow(c, self.d, self.n)

    def get_pubkey(self):
        return self.n

if __name__ == '__main__':
    rsa = RSA(2048)
    #msg = b'Test message to be encrypted 0123456789!, ' * 7
    msg=b'Test msg, '* 51
    msg_len = len(msg)
    print(f'msg={msg}')
    print(f'msg_len={msg_len}')
    print()
    msg_int = int.from_bytes(msg, byteorder='big')
    C = rsa.encrypt(msg_int)
    N = rsa.get_modulus()
    E = rsa.get_pub_exp()
    P = rsa.decrypt(C)
    print(f'msg_int={msg_int}')
    print(f'      P={P}')
    Pb = P.to_bytes(msg_len, byteorder='big')
    print(f'P decrypted normally = {Pb}')
    print()
    S = 311
    # S = random.randint(2, 2**1024-1) # It doesn't matter what S is
    Cprime = (pow(S, E, N)*C) % N
    Pprime = rsa.decrypt(Cprime)
    Sinv = extended_gcd(S, N) # Computing multiplicative inverse of S mod N
    P = (Pprime * Sinv) % N
    Pbytes = P.to_bytes(msg_len, byteorder='big')
    print(f'P decrypted otherwise = {Pbytes}')
