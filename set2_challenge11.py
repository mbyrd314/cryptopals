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

def encryption_oracle(msg, keysize):
    """
    Generates a random key of length keysize. The message has 5-10 bytes randomly
    appended to the start and end. The function then randomly encrypts the input
    message with either AES ECB or AES CBC mode. If CBC mode is used, a random IV
    is used. It is then determined whether the message was encrypted
    with ECB or CBC mode.

    Args:
        msg (bytes): Plaintext message to be encrypted
        keysize (int): Length of the secret key

    Returns:
        (bool): True if it correctly determines which AES mode was used
    """
    key = aes_keygen(keysize)
    used_ecb = False
    detected_ecb = False
    start_bytes = os.urandom(random.randint(5,10))
    end_bytes = os.urandom(random.randint(5,10))
    msg = start_bytes + msg + end_bytes
    if random.randint(0,1):
        #print('Encrypting CBC')
        iv = os.urandom(keysize)
        cmsg = encrypt_aes_cbc(msg, key, iv)
    else:
        #print('Encrypting ECB')
        used_ecb = True
        cmsg = encrypt_aes_ecb(msg, key)
    # for start_guess in range(5, 11):
    #     for end_guess in range(5, 11):
    #         new_cmsg = cmsg[start_guess:-end_guess]
    #         if detect_ecb(new_cmsg, keysize):
    #             detected_ecb = True
    detected_ecb = detect_ecb(cmsg, keysize)
    if used_ecb:
        if detected_ecb:
            pass
            #print('Success: ECB was used and detected')
        else:
            print('Failure: ECB was used and not detected')
    else:
        if detected_ecb:
            print('Failure: CBC was used, but ECB was detected')
        else:
            pass
            #print('Successs: CBC was used and detected')
    return used_ecb == detected_ecb

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
        #print('Error: Not integer number of blocks')
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

# For some reason, the detect_ecb function is not working, even though it is
# looking for repeated blocks like I did in challenge 8, where it did work.
if __name__ == '__main__':
    """
    The plaintext message that I use for this test is the html source for the
    Wikipedia page for cryptography. I originally used random messages of up to
    240 bytes long. These are too short for there to reliably be 16 byte long
    repeated segments, so there were no repeated blocks in the ciphertext and
    ECB encryption could not be detected.

    This iterates many times running the encryption oracle function to test if
    the oracle reliably works.
    """
    filename = '11.txt'
    with open(filename, 'rb') as f:
        msg = f.read()
    #print(msg)
    iters = 10000
    correct_count = 0
    for i in range(iters):
        if encryption_oracle(msg, keysize=16):
            correct_count += 1
        if not (i*10) % iters:
            x = (i*10) // iters
            print('%d Percent Done' % (x*10))
    correct_percentage = correct_count / iters * 100
    print(f'correct_count: {correct_count}, correct_percentage: {correct_percentage}')
