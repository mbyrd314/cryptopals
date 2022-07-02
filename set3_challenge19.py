from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode
import os

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
    # if diff == 0:
    #     diff = block_size
    # print(f'msg_len = {len(msg)}, pad_len = {diff}')
    b_msg = bytes(x for x in msg)
    #print(bytes([diff])*diff)
    b_msg += bytes([diff]) * diff
    # print(f'Orig: {msg}, Padded: {b_msg}')
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
    # print(f'Unpad: padding_size={padding_size}')
    # A message ending in a 0 byte is not correctly padded
    if padding_size == 0:
        raise ValueError('Not padded correctly')
    #print('padding_size: %d' % padding_size)
    for i in range(len(msg)-1, len(msg)-padding_size-1, -1):
        if msg[i] != padding_size:
            raise ValueError(f'Not padded correctly, padding_size: {padding_size}')
            # print('No Padding')
            # return msg
    #print('Padding Removed')
    new_msg = msg[:-padding_size]
    # print(f'Valid padding! Padded={msg}, pad_len={padding_size}')
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
    # msg = PKCS_7_pad(plaintext, block_size)
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
    # print(f'plaintext: {plaintext}')
    # print(f'msg: {msg}')
    # print(f'Mine: ptext={plaintext}, msg={msg}')
    num_blocks = len(msg) // block_size
    #print('block_size: %d, num_blocks: %d' % (block_size, num_blocks))
    blocks = [msg[block_size*i:block_size*(i+1)] for i in range(num_blocks)]
    #print(blocks)
    #print('len(blocks): %d' % len(blocks))
    cblocks = [b'\x00']*num_blocks
    #print('len(cblocks): %d' % len(cblocks))
    for i in range(num_blocks):
        #print('i: %d' % i)
        if i == 0:
            ctext = iv
        else:
            ctext = cblocks[i-1]
        cblocks[i] = encrypt_aes_ecb(xor_bytes(blocks[i], ctext), key)
    cmsg = b''
    for cblock in cblocks:
        cmsg += cblock
    #print(cmsg)
    #print(cblocks)
    return cmsg

def encrypt_aes_ctr(msg, key, nonce):
    """
    Encrypts bytes msg with passed key and nonce

    Args:
        msg (bytes): Msg to be encrypted
        key (bytes): Secret key to use for AES ECB encryption
        nonce (int): Nonce to be used for AES CTR mode encryption

    Returns:
        out (bytes): Encrypted output msg
    """
    keysize = len(key)
    ctr = 0
    out = b''
    # key_bytes = nonce.to_bytes(8, byteorder='little') + ctr.to_bytes(8, byteorder='little')
    # keystream = encrypt_aes_ecb(key_bytes, key)
    for i in range(len(msg)):
        idx = i % keysize
        if idx == 0:
            key_bytes = nonce.to_bytes(8, byteorder='little') + ctr.to_bytes(8, byteorder='little')
            keystream = encrypt_aes_ecb(key_bytes, key)
            ctr += 1
        # print(f'type(msg[i])={type(msg[i])}, type(keystream[i])={type(keystream[i])}')
        out += chr(msg[i] ^ keystream[idx]).encode()
    return out

if __name__ == '__main__':
    filename = '19.txt'
    key = os.urandom(16)
    nonce = 0
    ctexts = []
    print(f'Decoded Lines:')
    with open(filename, 'r') as f:
        lines = f.readlines()
        for line in lines:
            b = b64decode(line)
            print(f'{b}')
            ctext = encrypt_aes_ctr(b, key, nonce)
            ctexts.append(ctext)
    print()
    print(f'Encrypted Lines:')
    for ctext in ctexts:
        print(f'{ctext}')
