import random

class DH():
    def __init__(self, p, g):
        self.p = p
        self.g = g
        self.a = random.randint(0, p)
        self.A = pow(self.g, self.a, self.p)

    def get_pubkey(self):
        return self.A

    def keygen(self, B):
        self.key = pow(B, self.a, p)
        return self.key

# def diffie_hellman(p, g):
#     """
#     Implementation of Diffie-Hellman key exchange
#
#     Args:
#     p (int): prime modulus used to generate shared secret
#     g (int): base used to generate shared secret
#
#     Returns:
#     sa (int): shared secret key exchanged between the parties
#     """
#     a = random.randint(0, p)
#     A = pow(g, a, p)
#
#     b = random.randint(0, p)
#     B = pow(g, b, p)
#
#     sb = pow(A, b, p)
#     sa = pow(B, a, p)
#     assert(sa == sb)
#     return sa

if __name__ == '__main__':
    pb = b'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff'
    p = int.from_bytes(pb, byteorder='big')
    g = 2
    iters = 100
    for i in range(iters): # Testing that it does actually generate the same secret
        # diffie_hellman(p, g)
        A = DH(p, g)
        B = DH(p, g)
        assert(A.keygen(B.get_pubkey()) == B.keygen(A.get_pubkey()))
        if 10*(i+1) % iters == 0:
            pct = 100*(i+1)/iters
            print(f'{pct}% Done')
