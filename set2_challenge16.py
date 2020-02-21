from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode
import os, random, string
import urllib3, urllib

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
    return PKCS_7_unpad(msg)

def decrypt_aes_cbc(ciphertext, key, iv):
    """
    Implementing AES CBC mode using my AES ECB function

    Args:
        ciphertext (bytes): The ciphertext to be decrypted
        key (bytes): The AES secret key
        iv (bytes): The initialization vector for AES CBC mode

    Returns:
        bytes: The unpadded decrypted plaintext
    """
    block_size = len(key)
    num_blocks = len(ciphertext) // block_size
    #print('block_size: %d, num_blocks: %d' % (block_size, num_blocks))
    blocks = [ciphertext[block_size*i:block_size*(i+1)] for i in range(num_blocks)]
    #print(blocks)
    #print('len(blocks): %d' % len(blocks))
    pblocks = [b'\x00']*num_blocks
    #print('len(pblocks): %d' % len(pblocks))
    result = b''
    for i in range(num_blocks):
        #print('i: %d' % i)
        if i == 0:
            ctext = iv
        else:
            ctext = blocks[i-1]
        pblocks[i] = decrypt_aes_ecb(blocks[i], key)
        pblocks[i] = xor_bytes(pblocks[i], ctext)
        result += pblocks[i]
    return PKCS_7_unpad(result)

def make_cookie(msg, key, iv):
    """
    Appends the below defined prefix and suffix strings to the URL-encoded input msg
    string. Encrypts the new message in AES CBC mode with the key and iv parameters and
    returns the ciphertext.

    Args:
        msg (bytes): Plaintext message to be added between the prefix and suffix strings
                     and encrypted
        key (bytes): AES secret key to encrypt the message
        iv (bytes): Initialization vector to be used for AES CBC encryption

    Returns:
        (bytes): The encrypted cookie formed by AES CBC encryption of the prefix, msg, and suffix
    """
    keysize = len(key)
    prefix = b'comment1=cooking%20MCs;userdata='
    suffix = b';comment2=%20like%20a%20pound%20of%20bacon'
    msg = urllib.parse.quote(msg).encode() # Escaping characters to avoid obvious injection
    new_msg = prefix + msg + suffix
    return encrypt_aes_cbc(new_msg, key, iv)

def is_admin_cookie(cookie, key, iv):
    """
    Function to decrypt an input cookie with AES CBC mode. It then splits the string
    at semicolons and searches for the string 'admin=true'

    Args:
        cookie (bytes): Encrypted cookie to be checked for admin status
        key (bytes): AES secret key to decrypt the cookie
        iv (bytes): Initialization vector for the AES CBC decryption

    Returns:
        (bool): True if the cookie is admin, False otherwise
    """
    ptext = decrypt_aes_cbc(cookie, key, iv)
    #print(f'ptext: {ptext}')
    return b'admin=true' in ptext.split(b';')

if __name__ == '__main__':
    keysize = 16
    key = aes_keygen(keysize)
    iv = aes_keygen(keysize) # Since this function just returns random bytes of length keysize
    prefix = b'comment1=cooking%20MCs;userdata='
    suffix = b';comment2=%20like%20a%20pound%20of%20bacon'
    prefix_size = len(prefix)
    if prefix_size % keysize:
        prefix_padding = b'A'*(keysize-prefix_size%keysize)
    else:
        prefix_padding = b''
    num_prefix_blocks = len(prefix+prefix_padding) // keysize
    print(f'prefix_size: {prefix_size}, num_prefix_blocks: {num_prefix_blocks}')
    msg = b'A'*keysize # Making a block of all A's so that I can edit two bytes in the next block
    admin_string = b'1admin1true1' # Making the string that will be edited to ;admin=true
    admin_size = len(admin_string)
    admin_prefix = b'A'*(keysize-admin_size)
    #print(f'admin_size: {admin_size}, admin_prefix: {admin_prefix}')
    msg = prefix_padding + msg + admin_prefix + admin_string
    ctext = make_cookie(msg, key, iv)
    ptext = prefix+msg+suffix

    # Prefix blocks. These shouldn't be altered
    new_ctext = ctext[:keysize*num_prefix_blocks]

    # This is the block before my admin string
    edit_block = ctext[num_prefix_blocks*keysize:(num_prefix_blocks+1)*keysize]

    # Generating a block to xor with the edit_block so that it will decrypt to a string
    # containing the characters ;admin=true;
    xor_block = b'\x00'*(keysize-admin_size)
    xor_block += xor_bytes(b'1', b';')
    xor_block += b'\x00'*5
    xor_block += xor_bytes(b'1', b'=')
    xor_block += b'\x00'*4
    xor_block += xor_bytes(b'1', b';')

    # Xoring the two blocks before appending to the ciphertext
    new_ctext += xor_bytes(xor_block, edit_block)

    # Appending the rest of the ciphertext unaltered
    new_ctext += ctext[(num_prefix_blocks+1)*keysize:]

    # Checking to make sure that it is not an admin cookie before bit-flipping
    print(f'Admin before bit-flipping: {is_admin_cookie(ctext, key, iv)}')

    # Demonstrating that it is an admin cookie after bit-flipping
    print(f'Admin after bit-flipping {is_admin_cookie(new_ctext, key, iv)}')
