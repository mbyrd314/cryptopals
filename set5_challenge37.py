import random, cryptography, os
from cryptography.hazmat.primitives import hashes, hmac

class SRPClient():
    def __init__(self):
        Nb = b'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff'
        self.N = int.from_bytes(Nb, byteorder='big')
        self.g = 2
        self.k = 3
        self.I = b'randomtestemail@randomsite.com'
        self.P = b'testpasswordcorrecthorsebatterystapler'
        self.a = random.randint(1, self.N)
        self.A = pow(self.g, self.a, self.N)

    def send_email(self):
        print(f'Client sending email = {self.I}')
        print(f'Client sending A = {self.A}')
        print()
        return self.I, self.A

    def recv_salt(self, salt, B):
        self.salt = salt
        self.B = B
        print(f'Client received salt = {self.salt}')
        print(f'Client received B = {self.B}')
        print()

    def compute_u(self):
        self.Abytes = self.A.to_bytes(512, byteorder='big')
        self.Bbytes = self.B.to_bytes(512, byteorder='big')
        h = hashes.Hash(hashes.SHA256())
        h.update(self.Abytes+self.Bbytes)
        uH = h.finalize()
        self.u = int.from_bytes(uH, byteorder='big')
        print(f'Client computed u = {self.u}')
        print()

    def compute_K(self):
        h = hashes.Hash(hashes.SHA256())
        salt_bytes = self.salt.to_bytes(8, byteorder='big')
        h.update(salt_bytes+self.P)
        xH = h.finalize()
        self.x = int.from_bytes(xH, byteorder='big')
        S = (self.B-self.k*pow(self.g, self.x, self.N))%self.N
        S = pow(S, self.a + self.u * self.x, self.N)
        S = 0 # We know that the server is going to compute a value of 0 for S
        h = hashes.Hash(hashes.SHA256())
        Sbytes = S.to_bytes(512, byteorder='big')
        print(f'Client computed S = {S}')
        print(f'In bytes: {Sbytes}')
        h.update(Sbytes)
        self.K = h.finalize()
        print(f'Client computed K = {self.K}')
        print()

    def send_mac(self):
        h = hmac.HMAC(self.K, hashes.SHA256())
        salt_bytes = self.salt.to_bytes(8, byteorder='big')
        h.update(salt_bytes)
        h_copy = h.copy()
        signature = h.finalize()
        print(f'Client sending signature = {signature}')
        try:
            h_copy.verify(signature)
            print(f'Client verified its own signature!')
        except cryptography.exceptions.InvalidSignature:
            print(f'Client somehow could not verify its own signature')
        print()
        return signature


class SRPServer():
    def __init__(self):
        Nb = b'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff'
        self.N = int.from_bytes(Nb, byteorder='big')
        self.g = 2
        self.k = 3
        self.I = os.urandom(20) # Using random email and password
        self.P = os.urandom(20)
        # self.I = b'randomtestemail@randomsite.com'
        # self.P = b'testpasswordcorrecthorsebatterystapler'
        self.salt = random.randint(2**63, 2**64-1) # Generate a random 64-bit salt
        h = hashes.Hash(hashes.SHA256())
        salt_bytes = self.salt.to_bytes(8, byteorder='big')
        h.update(salt_bytes+self.P)
        xH = h.finalize()
        x = int.from_bytes(xH, byteorder='big')
        self.v = pow(self.g, x, self.N)

    def recv_email(self, I, A):
        self.A = A
        print(f'Server received A = {self.A}')
        print()

    def send_salt(self):
        self.b = random.randint(1, self.N)
        self.B = (self.k*self.v + pow(self.g, self.b, self.N)) % self.N
        print(f'Server sending salt = {self.salt}')
        print(f'Server sending B = {self.B}')
        print()
        return self.salt, self.B

    def compute_u(self):
        self.Abytes = self.A.to_bytes(512, byteorder='big')
        self.Bbytes = self.B.to_bytes(512, byteorder='big')
        h = hashes.Hash(hashes.SHA256())
        h.update(self.Abytes+self.Bbytes)
        uH = h.finalize()
        self.u = int.from_bytes(uH, byteorder='big')
        print(f'Server computed u = {self.u}')
        print()

    def compute_K(self):
        S = (self.A * pow(self.v, self.u, self.N)) % self.N
        S = pow(S, self.b, self.N)
        Sbytes = S.to_bytes(512, byteorder='big')
        print(f'Server computed S = {S}')
        print(f'In bytes: {Sbytes}')
        h = hashes.Hash(hashes.SHA256())
        h.update(Sbytes)
        self.K = h.finalize()
        print(f'Server computed K = {self.K}')
        print()

    def validate_mac(self, signature):
        h = hmac.HMAC(self.K, hashes.SHA256())
        salt_bytes = self.salt.to_bytes(8, byteorder='big')
        h.update(salt_bytes)
        print(f'Server received signature = {signature}')
        try:
            h.verify(signature)
            print(f'Signature validated!')
        except cryptography.exceptions.InvalidSignature:
            print(f'Signature not valid!')

if __name__ == '__main__':
    client = SRPClient()
    server = SRPServer()
    I, A = client.send_email()
    server.recv_email(I, 0) # Sending a value of 0 for A
    salt, B = server.send_salt()
    client.recv_salt(salt, B)
    client.compute_u()
    server.compute_u()
    client.compute_K()
    server.compute_K()
    signature = client.send_mac()
    server.validate_mac(signature)
    # With the value of 0 passed for A, the server validates the client's signature, even though
    # the password and email it used were random
