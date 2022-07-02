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


    def encrypt(self, m):
        return pow(m, self.e, self.n)

    def decrypt(self, c):
        return pow(c, self.d, self.n)

if __name__ == '__main__':
    bit_lens = [4, 8, 16, 32, 64, 128, 256, 512, 1024]
    for l in bit_lens:
        p = generate_prime(l)
        print(f'Generating {l} bit prime')
        print(f'Bit length = {l}, prime = {p}')
    for i in range(100): # Testing that decrypting the encrypted msg does produce the original message
        print()
        test_msg = random.randint(1,2**64-1)
        rsa = RSA(size=512)
        c = rsa.encrypt(test_msg)
        m = rsa.decrypt(c)
        print(f'test_msg={test_msg}, c={c}, m={m}')
    # x = extended_gcd(17, 3120)
    # print(f'x={x}')
