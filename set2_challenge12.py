from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode
import os, random, string

def aes_keygen(keysize):
    """
    Generates a random key of length keysize

    Args:
        keysize (int): Length of the desired key in bytes

    Returns:
        (bytes): A generated key of length keysize
    """
    return os.urandom(keysize)

def encryption_oracle(msg, key):
    """
    Encrypts the string with an unknown but consistent secret key

    Args:
        msg (bytes): Message to be encrypted
        key (bytes): Secret key to use for the encryption

    Returns:
        (bytes): The encrypted ciphertext
    """

    return encrypt_aes_ecb(msg, key)

def detect_block_size(unknown_string, key):
    """
    Detects block size used by the unknown string.

    Args:
        key (bytes): Secret key to use for AES ECB encryption

    Returns:
        (int): Block size of the encryption cipher
    """
    msg = b''
    prev_size = len(encryption_oracle(msg+unknown_string, key))
    i = 1
    #print(f'prev_size: {prev_size}')
    while True:
        msg += b'A'
        new_size = len(encryption_oracle(msg+unknown_string, key))
        #print(f'i: {i}, new_size: {new_size}')
        if new_size > prev_size:
            #print(f'block_size: {new_size-prev_size}, i: {i}')
            return new_size - prev_size
        i += 1
        if i % 20 == 0:
            print(f'i: {i}, new_size: {new_size}')
        assert(i!=5000), 'This should never happen'
    return -1


def detect_ecb(msg, keysize):
    """
    Detects AES ECB mode encryption with a given keysize. It does this by finding
    repeated blocks of length keysize in the ciphertext.

    Args:
        msg (bytes): Encrypted message to be checked for ECB encryption
        keysize (int): Length of the key used for the encryption

    Returns:
        (bool): True if ECB is detected, False otherwise
    """
    if len(msg) % keysize:
        print('Error: Not integer number of blocks')
        return False
    num_blocks = len(msg) // keysize
    blocks = [msg[i*16:(i+1)*16] for i in range(num_blocks)]
    #print(f'len(msg): {len(msg)}, num_blocks: {num_blocks}')
    #print(blocks)
    if len(set(blocks)) != num_blocks: # There is a duplicate block
        return True
    else:
        return False



def PKCS_7_pad(msg, block_size):
    """
    Implementation of PKCS7 padding

    Args:
        msg (bytes): Message to be padded
        block_size (bytes): Block size that the message needs to be padded to

    Returns:
        b_msg (bytes): PKCS padded version of the input message
    """
    if len(msg) > block_size:
        diff = block_size - len(msg) % block_size
    else:
        diff = block_size - len(msg)
    #print(diff)
    b_msg = msg
    #print(bytes([diff])*diff)
    b_msg += bytes([diff]) * diff
    #print(b_msg)
    return b_msg

def PKCS_7_unpad(msg):
    """
    Undoes PKCS7 padding

    Args:
        msg (bytes): Message to be unpadded. If not padded with PKCS7, returns the original message

    Returns:
        new_msg (bytes): Returns either the unpadded version of the original message
                         or the original message if not padded
    """
    padding_size = msg[-1]
    #print('padding_size: %d' % padding_size)
    for i in range(len(msg)-1, len(msg)-padding_size-1, -1):
        if msg[i] != padding_size:
            #print('No Padding')
            return msg
    #print('Padding Removed')
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
    msg = PKCS_7_pad(plaintext, block_size)
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
    #print(msg)
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

if __name__ == '__main__':
    """
    Does byte at a time ECB decryption. If something is encrypted as AES_ECB(Input+SECRET),
    this method can determine the SECRET message even without knowing the key.
    """
    unknown_string = b'''Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK'''
    unknown_string = b64decode(unknown_string)
    key = aes_keygen(16)
    block_size = detect_block_size(unknown_string, key)
    msg = b'A'*2*block_size # To ensure that there are two repeating blocks
    msg += unknown_string
    msg = PKCS_7_pad(msg, block_size)
    if detect_ecb(msg, block_size):
        print('ECB correctly detected')
    else:
        print('ECB not detected')
    # So ECB encryption has been successfully detected.
    unknown_size = len(encryption_oracle(unknown_string, key))
    prefix = b'A'*(block_size)
    ctext = encryption_oracle(prefix+unknown_string, key)
    print(f'unknown_size: {unknown_size}')
    hidden_text = b''
    for i in range(unknown_size-1, -1, -1):
        prefix = b'A'*i # Number of leading A's decreases every time a new character is deciphered
        ctext = encryption_oracle(prefix+unknown_string, key)[:unknown_size]
        for j in range(256):
            byte = chr(j).encode()
            new_text = prefix+hidden_text+byte+unknown_string
            new_ctext = encryption_oracle(new_text, key)
            if new_ctext[:unknown_size] == ctext:
                hidden_text += byte
                break
    print(f'hidden_text: {PKCS_7_unpad(hidden_text).decode()}')
    # Successfully determines the unknown string
