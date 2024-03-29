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
    # print(f'decrypted: {result}')
    return PKCS_7_unpad(result)

def lib_enc_aes_cbc(ptext, key, iv):
    block_size = len(key)
    msg = PKCS_7_pad(ptext, block_size)
    print(f'Lib:  ptext={ptext}, msg={msg}')
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    msg = encryptor.update(msg) + encryptor.finalize()
    return msg

def lib_dec_aes_cbc(ciphertext, key, iv):
    """
    Using the built-in library version of AES CBC to compare to my version

    Args:
        ciphertext (bytes): The ciphertext to be decrypted
        key (bytes): The AES secret key
        iv (byte): The initialization vector for AES CBC mode

    Returns:
        msg (bytes): The unpadded decrypted plaintext

    """
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    msg = decryptor.update(ciphertext) + decryptor.finalize()
    print(f'Lib msg = {msg}')
    return PKCS_7_unpad(msg)

def make_cookie(filename, key, iv):
    """
    Randomly chooses one of the strings from the input file. Encrypts the string
    in AES CBC mode with the input key and iv.

    Args:
        filename (str): File containing 10 strings from which one will be randomly chosen
                        and encrypted
        key (bytes): AES secret key to encrypt the random string
        iv (bytes): Initialization vector to be used in the AES CBC encryption

    Returns:
        cookie (bytes): Encrypted version of the randomly chosen string
        iv (bytes): The initialization vector used in the encryption
    """
    with open(filename, 'r') as f:
        lines = f.readlines()
        num = random.randint(0,9)
        msg = b64decode(lines[num])
    cookie = encrypt_aes_cbc(msg, key, iv)
    return cookie, iv

def padding_oracle(cookie, key, iv):
    """
    Decrypts an input cookie and returns True or False depending on if the padding
    is valid.

    Args:
        cookie (bytes): AES CBC encrypted cookie
        key (bytes): AES secret key to decrypt the cookie
        iv (bytes): Initialization vector to be used in the AES CBC decryption

    Returns:
        (bool): True if the padding is valid on the decrypted cookie, False otherwise
    """
    try:
        ptext = decrypt_aes_cbc(cookie, key, iv)
        # print('Valid padding!')
        # print(f'ptext: {ptext.decode()}')
        return True
    except UnicodeDecodeError:
        # print(f'ptext: {ptext}')
        return True
    except ValueError as err:
        # print(f'Err: {err}')
        return False

def lib_oracle(cookie, key, iv):

    try:
        ptext = lib_dec_aes_cbc(cookie, key, iv)
        print('Valid padding!')
        print(f'ptext: {ptext.decode()}')
        return True
    except UnicodeDecodeError:
        return True
    except ValueError as err:
        print(f'Err: {err}')
        return False

def single_block_oracle_decrypt(C1, C2, key, iv):
    """
    Implementation of the CBC padding oracle decryption attack. Decrypts block2 by
    editing the bytes of block1 so that the padding oracle says that the decrypted
    plaintext of the concatenation of the two blocks has valid padding.

    Args:
        C1 (bytes): Ciphertext block preceding the block to be decrypted
        C2 (bytes): Ciphertext block to be decrypted
        key (bytes): AES secret key to decrypt the ciphertext
        iv (bytes): Initialization vector to be used in AES CBC decryption

    Returns:
        ptext (bytes): Decrypted plaintext of block2
    """
    ptext = b''
    keysize = len(key)
    I2 = b''
    C1prime = os.urandom(keysize)
    prefix = C1prime
    # print(f'C1 = {C1}, len={len(C1)}')
    # print(f'C2 = {C2}, len={len(C2)}')
    for i in range(1,keysize+1):
        prefix = prefix[:-1]
        suffix = chr(i).encode()*len(I2)
        # print(f'i: {i}, prefix: {prefix}, suffix: {suffix}')
        if len(I2) > 0:
            suffix = xor_bytes(suffix, I2)
            # print(f'I2 = {I2}, suffix = {suffix}')
        # else:
        #     print('I2 = None')
        # print(f'prefix: {prefix}, len={len(prefix)}')
        # print(f'suffix: {suffix}, len={len(suffix)}')
        for j in range(256):
            # print(f'j = {j}')
            cbyte = (j).to_bytes(1,byteorder='big')
            C1prime = prefix + cbyte + suffix
            msg = C1prime + C2
            # if j == 0 or j == 1 or j == 131 or j == 65 or j == 128 or j == 127: # Debugging where I found out that chr(x) for x >127 is two bytes
            #     print(f'i={i},j={j}, msg: {msg}, len(msg): {len(msg)}')
            #     # print(f'len(msg): {len(msg)}')
            if padding_oracle(msg, key, iv):
                # print(f'Oracle Passed: i: {i}, j: {j}, C1prime: {C1prime}, msg={msg}')
                new_byte = xor_bytes(cbyte, chr(i).encode())
                I2 = new_byte + I2
                new_pbyte = xor_bytes(new_byte, chr(C1[16-i]).encode())
                # print(f'I2: {I2}, P2[{16-i}]={new_pbyte}')
                break
    ptext = xor_bytes(I2, C1)
    print(f'Single Block Decrypted: ptext = {ptext}')
    return ptext

def oracle_decrypt(ctext, key, iv):
    """
    Uses the single block padding oracle decryption function on every pair of blocks
    in the ciphertext. To decrypt the first ciphertext block, the preceding block
    is the IV.

    Args:
        ctext (bytes): Ciphertext to be decrypted
        key (bytes): AES secret key to decrypt the ciphertext
        iv (bytes): Initialization vector to be used in AES CBC decryption

    Returns:
        ptext (bytes): The decrypted plaintext of the ciphertext input
    """
    ptext = b''
    # prev = iv
    keysize = len(key)
    num_blocks = len(ctext) // keysize
    blocks = [ctext[keysize*i:keysize*(i+1)] for i in range(1, num_blocks)]
    prev = ctext[:keysize]
    # print(f'prev={prev}')
    # print(f'blocks={blocks}')
    for block in blocks:
        ptext += single_block_oracle_decrypt(prev, block, key, iv)
        # print(f'ptext: {ptext}')
        prev = block
    return PKCS_7_unpad(ptext)

if __name__ == '__main__':
    """
    Implementation of the CBC padding oracle attack. Randomly chooses one of the
    strings from the file 17.txt, encrypts them with AES CBC mode, and then decrypts
    them with the padding oracle attack.
    """
    keysize = 16
    key = aes_keygen(keysize)
    iv = aes_keygen(keysize)
    # key = b'YELLOW SUBMARINE'
    # iv = key
    filename = '17.txt'
    iters = 100
    trueCount = 0
    falseCount = 0
    libTrue = 0
    libFalse = 0

    # s = 'test'
    # bs = s.encode()
    # print(f'type(s) = {type(s)}, type(bs) = {type(bs)}')

    # Testing the padding oracle on several valid messages
    # for i in range(iters):
    #     cookie, iv = make_cookie(filename, key, iv)
    #     # libCookie =
    #     if padding_oracle(cookie, key, iv):
    #         trueCount += 1
    #     else:
    #         falseCount += 1
    #     if lib_oracle(cookie, key, iv):
    #         libTrue += 1
    #     else:
    #         libFalse += 1
    # truePercent = trueCount / (iters) * 100
    # falsePercent = falseCount / (iters) * 100
    # print(f'My Dec:  {trueCount}/{iters} ({truePercent}%) correct')
    # print(f'My Dec:  {falseCount}/{iters} ({falsePercent}%) false')
    # libTruePercent = libTrue / (iters) * 100
    # libFalsePercent = libFalse / (iters) * 100
    # print(f'Lib Dec: {libTrue}/{iters} ({libTruePercent}%) correct')
    # print(f'Lib Dec: {libFalse}/{iters} ({libFalsePercent}%) false')
    # cookie, iv = make_cookie(filename, key, iv)
    # phrase = b'YELLOW SUBMARINE'*7
    phrase = b''
    for i in range(7):
        phrase += b'YELLOWSUBMARINE'
        phrase += str(i).encode()
    cookie = encrypt_aes_cbc(phrase, key, iv)
    num_blocks = len(cookie) // keysize
    block1 = cookie[5*keysize:6*keysize]
    block2 = cookie[6*keysize:7*keysize]
    # ptext_block2 = single_block_oracle_decrypt(block1, block2, key, iv)
    # try:
    #     print(f'b2 = {ptext_block2.decode()}')
    # except UnicodeDecodeError:
    #     print(f"Couldn't decode decrypted block. b2={ptext_block2}")

    # phrase = b'YELLOW SUBMARINE'
    # p_cookie = encrypt_aes_cbc(phrase, key, iv)
    # lib_cookie = lib_enc_aes_cbc(phrase, key, iv)
    # print(f'mine: {p_cookie}')
    # print(f'lib:  {lib_cookie}')
    # if padding_oracle(p_cookie, key, iv):
    #     print(f'Cookie was padded correctly')
    # else:
    #     print(f'Cookie was somehow not padded correctly')
    # if padding_oracle(lib_cookie, key, iv):
    #     print(f'Lib cookie was padded correctly')
    # else:
    #     print(f'Lib cookie was somehow not padded correctly')
    # lib_phrase = lib_dec_aes_cbc(p_cookie, key, iv)
    # print(f'lib_phrase = {lib_phrase}')
    # d_phrase = decrypt_aes_cbc(p_cookie, key, iv)
    # print(f'd_phrase = {d_phrase}')


    # Comparing decryption with the known key to decryption with the padding oracle
    # These should be the same.
    key_ptext = decrypt_aes_cbc(cookie, key, iv)
    print(f'key_ptext: \t{key_ptext}')
    pad_ptext = oracle_decrypt(cookie, key, iv)
    print(f'pad_ptext: \t{pad_ptext}')
    print(f'phrase: \t{phrase}')

    for i in range(iters):
        cookie, iv = make_cookie(filename, key, iv)
        key_ptext = decrypt_aes_cbc(cookie, key, iv)
        pad_ptext = oracle_decrypt(cookie, key, iv)
        print(f'key_ptext = {key_ptext}')
        print(f'pad_ptext = {pad_ptext}')
