import random, os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode

def left_rotate(msg, shift):
    return ((msg << shift) | (msg >> (32-shift))) & (0xFFFFFFFF)

def sha1(msg):
    MAX_VAL = 0xFFFFFFFF
    h0 = int.from_bytes(b'\x67\x45\x23\x01', byteorder='big')
    h1 = int.from_bytes(b'\xEF\xCD\xAB\x89', byteorder='big')
    h2 = int.from_bytes(b'\x98\xBA\xDC\xFE', byteorder='big')
    h3 = int.from_bytes(b'\x10\x32\x54\x76', byteorder='big')
    h4 = int.from_bytes(b'\xC3\xD2\xE1\xF0', byteorder='big')
    ml = len(msg)*8 # Length of msg in bits

    pad_size = -(ml + 1 + 64) % 512
    padded_msg = msg + b'\x80' + b'\x00'*(pad_size//8) + ml.to_bytes(8, byteorder='big')

    for i in range(len(padded_msg)//64):
        chunk = padded_msg[64*i:64*(i+1)]
        w = []
        for j in range(16):
            new_word_bytes = chunk[4*j:4*(j+1)]
            new_word = int.from_bytes(new_word_bytes, byteorder='big')
            w.append(new_word)

        for j in range(16, 80):
            new_word = left_rotate(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1)
            w.append(new_word)
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        for j in range(80):
            if j >= 0 and j < 20:
                f = (b & c) | (~b & d)
                k = 0x5A827999
            elif j >= 20 and j < 40:
                f = (b ^ c ^ d)
                k = 0x6ED9EBA1
            elif j >= 40 and j < 60:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (left_rotate(a, 5) + f + e + k + w[j]) & MAX_VAL
            e = d
            d = c
            c = left_rotate(b, 30)
            b = a
            a = temp

        h0 = (h0 + a) & MAX_VAL
        h1 = (h1 + b) & MAX_VAL
        h2 = (h2 + c) & MAX_VAL
        h3 = (h3 + d) & MAX_VAL
        h4 = (h4 + e) & MAX_VAL
    hh = (h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32) | h4
    return hh

def PKCS_7_pad(msg, block_size):
    """
    Implementation of PKCS7 padding

    Args:
        msg (bytes): Message to be padded
        block_size (bytes): Block size that the message needs to be padded to

    Returns:
        b_msg (bytes): PKCS padded version of the input message
    """
    if len(msg) >= block_size:
        diff = block_size - len(msg) % block_size
    else:
        diff = block_size - len(msg)
    b_msg = bytes(x for x in msg)
    b_msg += bytes([diff]) * diff
    return b_msg

def PKCS_7_unpad(msg):
    """
    Undoes PKCS7 padding

    Args:
        msg (bytes): Message to be unpadded.

    Raises:
        ValueError: If message is not padded with PKCS#7, raises ValueError

    Returns:
        new_msg (bytes): Returns either the unpadded version of the original message
                         or the original message if not padded
    """
    padding_size = msg[-1]
    if padding_size == 0:
        raise ValueError('Not padded correctly')
    for i in range(len(msg)-1, len(msg)-padding_size-1, -1):
        if msg[i] != padding_size:
            raise ValueError(f'Not padded correctly, padding_size: {padding_size}')
    new_msg = msg[:-padding_size]
    return new_msg

def encrypt_aes_ecb(plaintext, key):
    """
    Implementation of AES ECB mode encryption using the Python cryptography library

    Args:
        plaintext (bytes): The plaintext message to be encrypted
        key (bytes): The AES secret key

    Returns:
        cmsg (bytes): The encrypted ciphertext of the plaintext input
    """
    block_size = len(key)
    msg = bytes(x for x in plaintext)
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()
    cmsg = encryptor.update(msg) + encryptor.finalize()
    return cmsg


def xor_bytes(byte1, byte2):
    """
    XORs two bytestrings and returns the result

    Args:
        byte1 (bytes): The first bytestring to be XORed
        byte2 (bytes): The second bytestring to be XORed

    Returns:
        bytes: The result of XORing the two inputs
    """
    return bytes(a^b for a,b in zip(byte1, byte2))

def encrypt_aes_cbc(plaintext, key, iv):
    """
    Implementing AES CBC encryption using my AES ECB function

    Args:
        plaintext (bytes): The plaintext message to be encrypted
        key (bytes): The AES secret key
        iv (bytes): The initialization vector for AES CBC mode

    Returns:
        cmsg (bytes): The encrypted version of the plaintext input
    """
    block_size = len(key)
    msg = PKCS_7_pad(plaintext, block_size)
    num_blocks = len(msg) // block_size
    blocks = [msg[block_size*i:block_size*(i+1)] for i in range(num_blocks)]
    cblocks = [b'\x00']*num_blocks
    for i in range(num_blocks):
        if i == 0:
            ctext = iv
        else:
            ctext = cblocks[i-1]
        cblocks[i] = encrypt_aes_ecb(xor_bytes(blocks[i], ctext), key)
    cmsg = b''
    for cblock in cblocks:
        cmsg += cblock
    return cmsg

def decrypt_aes_ecb(ciphertext, key):
    """
    Implementation of AES ECB mode decryption using the Python cryptography library

    Args:
        ciphertext (bytes): The ciphertext message to be decrypted
        key (bytes): The AES secret key

    Returns:
        msg (bytes): The decrypted version of the ciphertext input
    """
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    msg = decryptor.update(ciphertext) + decryptor.finalize()
    return msg

def decrypt_aes_cbc(ciphertext, key, iv):
    """
    Implementing AES CBC mode using my AES ECB function

    Args:
        ciphertext (bytes): The ciphertext to be decrypted
        key (bytes): The AES secret key
        iv (bytes): The initialization vector for AES CBC mode

    Returns:
        (bytes): The unpadded decrypted plaintext
    """
    block_size = len(key)
    num_blocks = len(ciphertext) // block_size
    blocks = [ciphertext[block_size*i:block_size*(i+1)] for i in range(num_blocks)]
    pblocks = [b'\x00']*num_blocks
    result = b''
    for i in range(num_blocks):
        if i == 0:
            ctext = iv
        else:
            ctext = blocks[i-1]
        pblocks[i] = decrypt_aes_ecb(blocks[i], key)
        pblocks[i] = xor_bytes(pblocks[i], ctext)
        result += pblocks[i]
    return PKCS_7_unpad(result)

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

class A():
    def __init__(self, p, g):
        self.DH = DH(p, g)
        self.msg = b'Test Message, '* 11
        print(f'Initializing A')
        print(f'p={p}')
        print(f'g={g}')
        print(f'A={self.DH.get_pubkey()}')
        print()

    def send_params(self):
        return p, g

    def send_pubkey(self):
        return self.DH.get_pubkey()

    def recv_pubkey(self, Bval):
        self.secret = self.DH.keygen(Bval).to_bytes(1024, byteorder='big')

    def send_msg(self):
        self.key = sha1(self.secret).to_bytes(20, byteorder='big')[:16]
        self.iv = os.urandom(16)
        self.ctext = encrypt_aes_cbc(self.msg, self.key, self.iv) + self.iv
        print(f'A: key={self.key}')
        print(f'A sent msg {self.msg} to B')
        print(f'Length of A ctext = {len(self.ctext)}')
        return self.ctext

    def recv_msg(self, ctext):
        Biv = ctext[-16:]
        Bmsg = decrypt_aes_cbc(ctext[:-16], self.key, Biv)
        print(f'A received msg {Bmsg} from B')

class B():
    def __init__(self, p, g):
        self.DH = DH(p, g)
        print(f'Initializing B')
        print(f'p={p}')
        print(f'g={g}')
        print(f'B={self.DH.get_pubkey()}')
        print()

    def send_ack(self):
        print(f'B acknowledges params from A')

    def recv_pubkey(self, Aval):
        self.secret = self.DH.keygen(Aval).to_bytes(1024, byteorder='big')
        self.key = sha1(self.secret).to_bytes(20, byteorder='big')[:16]
        self.iv = os.urandom(16)
        print(f'B: key={self.key}')

    def send_pubkey(self):
        return self.DH.get_pubkey()

    def recv_msg(self, Actext):
        Aiv = Actext[-16:]
        Amsg = decrypt_aes_cbc(Actext[:-16], self.key, Aiv)
        self.msg = Amsg
        print(f'B received msg {Amsg} from A')

    def send_msg(self):
        self.ctext = encrypt_aes_cbc(self.msg, self.key, self.iv) + self.iv
        return self.ctext

class M():
    def __init__(self, p, g, Aval):
        print(f'Initializing M')
        print(f'p={p}')
        print(f'g={g}')
        # print(f'Aval={Aval}')
        self.DH = DH(p, g)
        self.p = p
        self.g = g

    def send_params_B(self):
        return self.p, self.g

    def recv_pubkey_B(self, Bval):
        self.Bval = Bval

    def send_pubkey_B(self):
        return self.Aval

    def recv_pubkey_A(self, Aval):
        self.Aval = Aval
        self.secret = self.DH.keygen(p).to_bytes(1024, byteorder='big')
        self.key = sha1(self.secret).to_bytes(20, byteorder='big')[:16]
        print(f'M: key={self.key}')

    def send_pubkey_A(self):
        return self.Bval

    def recv_msg_A(self, Actext):
        self.Actext = Actext
        Aiv = Actext[-16:]
        Amsg = decrypt_aes_cbc(Actext[:-16], self.key, Aiv)
        print(f'M received msg {Amsg} from A')

    def send_msg_B(self):
        return self.Actext

    def recv_msg_B(self, Bctext):
        self.Bctext = Bctext
        Biv = Bctext[-16:]
        Bmsg = decrypt_aes_cbc(Bctext[:-16], self.key, Biv)
        print(f'M received msg {Bmsg} from B')

    def send_msg_A(self):
        return self.Bctext

def MITM_g(new_g):
    pb = b'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff'
    p = int.from_bytes(pb, byteorder='big')
    g = 2
    Abot = A(p, g)
    Mbot = M(p, new_g, Abot.send_pubkey())
    Bbot = B(*Mbot.send_params_B())
    Bbot.send_ack()
    Mbot.recv_pubkey_A(Abot.send_pubkey())
    Bbot.recv_pubkey(Mbot.send_pubkey_B())
    Mbot.recv_pubkey_B(Bbot.send_pubkey())
    Abot.recv_pubkey(Mbot.send_pubkey_A())
    Mbot.recv_msg_A(Abot.send_msg())
    Bbot.recv_msg(Mbot.send_msg_B())
    Mbot.recv_msg_B(Bbot.send_msg())
    Abot.recv_msg(Mbot.send_msg_A())

if __name__ == '__main__':
    # Regular protocol with no MITM
    pb = b'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff'
    p = int.from_bytes(pb, byteorder='big')
    g = 2
    Abot = A(p, g)
    Bbot = B(*Abot.send_params())
    Bbot.send_ack()
    Bbot.recv_pubkey(Abot.send_pubkey())
    Abot.recv_pubkey(Bbot.send_pubkey())
    Bbot.recv_msg(Abot.send_msg())
    Abot.recv_msg(Bbot.send_msg())

    # Same protocol with MITM
    for new_g in [p, p-1]:
        print(f'Doing MITM with g = {new_g}')
        print()
        MITM_g(new_g)
