from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode
import os, random, string

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
    # print('padding_size: %d' % padding_size)
    for i in range(len(msg)-1, len(msg)-padding_size-1, -1):
        if msg[i] != padding_size:
            #print('No Padding')
            return msg
    #print('Padding Removed')
    new_msg = msg[:-padding_size]
    return new_msg

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

def encrypt_aes_ecb(plaintext, key):
    """
    Implementation of AES ECB mode encryption using the Python cryptography library

    Args:
        plaintext (bytes): The plaintext message to be encrypted
        key (bytes): The AES secret key

    Returns:
        cmsg (bytes): The encrypted ciphertext of the plaintext input
    """
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()
    cmsg = encryptor.update(plaintext) + encryptor.finalize()
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
    return PKCS_7_unpad(msg)

def lib_enc_aes_cbc(ptext, key, iv):
    block_size = len(key)
    msg = PKCS_7_pad(ptext, block_size)
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    msg = encryptor.update(msg) + encryptor.finalize()
    return msg



if __name__ == '__main__':
    """
    Main function that decrypts the given text file with AES CBC mode with the
    indicated key and IV.

    The function then tests the AES encryption and decryption on several random
    messages of random lengths with random keys and random IVs to make sure that
    encrypting and decrypting a message returns the original message.
    """
    iters = 10000
    filename = 'set2_challenge10.txt'
    with open(filename, 'rb') as f:
        iv = b'\x00'*16
        key = b'YELLOW SUBMARINE'
        emsg = f.read()
        emsg = b64decode(emsg)
        # print(emsg)
        my_msg = decrypt_aes_cbc(emsg, key, iv)
        lib_msg = lib_dec_aes_cbc(emsg, key, iv)
        # print(f'mine = {my_msg}')
        # print(f'lib =  {lib_msg}')
        # print(f'same = {my_msg==lib_msg}')
    # Testing on several random messages of random lengths with random keys and random ivs
    true_count = true_rate = 0
    false_count = false_rate = 0
    # for i in range(iters):
    #     length = random.randint(1000, 10000)
    #     msg = os.urandom(length)
    #     key = os.urandom(16)
    #     iv = os.urandom(16)
    #     # assert(decrypt_aes_cbc(encrypt_aes_cbc(msg, key, iv), key, iv) == msg)
    #     if decrypt_aes_cbc(encrypt_aes_cbc(msg, key, iv), key, iv) == msg:
    #         true_count += 1
    #     else:
    #         false_count += 1
    #         # print(f'')
    #     # This should be working since there are no assertion errors on random msgs
    #     # with random keys and random ivs
    #     if not (i*10) % iters:
    #         x = (i*100) // iters
    #         true_rate = true_count / iters * 100
    #         false_rate = false_count / iters * 100
    #         print(f'{x}% Done. True rate = {true_rate}, False rate = {false_rate}')
    # true_rate = true_count / iters * 100
    # false_rate = false_count / iters * 100
    # print(f'Complete: {iters} iterations successful. True rate = {true_rate}, False rate = {false_rate}')
    # enc_same = enc_rate = 0
    # dec_same = dec_rate = 0
    # my_idemp = my_rate = 0
    # lib_idemp = lib_rate = 0
    # for i in range(iters):
    #     length = random.randint(1000, 10000)
    #     msg = os.urandom(length)
    #     key = os.urandom(16)
    #     iv = os.urandom(16)
    #     my_enc = encrypt_aes_cbc(msg, key, iv)
    #     lib_enc = lib_enc_aes_cbc(msg, key, iv)
    #     my_dec = decrypt_aes_cbc(my_enc, key, iv)
    #     lib_dec = lib_dec_aes_cbc(lib_enc, key, iv)
    #     if my_enc == lib_enc:
    #         enc_same += 1
    #     if my_dec == lib_dec:
    #         dec_same += 1
    #     if my_dec == msg:
    #         my_idemp += 1
    #     if lib_dec == msg:
    #         lib_idemp += 1
    #     if ((i+1)*10) % iters == 0:
    #         x = ((i+1)*100) // iters
    #         enc_true_rate = enc_same / iters * 100
    #         enc_false_rate = ((i-enc_same) / iters) * 100
    #         dec_true_rate = dec_same / iters * 100
    #         dec_false_rate = ((i-dec_same) / iters) * 100
    #         my_idemp_true_rate = my_idemp / iters * 100
    #         my_idemp_false_rate = ((i-my_idemp) / iters) * 100
    #         lib_idemp_true_rate = lib_idemp / iters * 100
    #         lib_idemp_false_rate = ((i-lib_idemp) / iters) * 100
    #         print(f'{x}% Done! Enc: {enc_true_rate}% True / {enc_false_rate}% False, Dec: {dec_true_rate}% True / {dec_false_rate}% False')
    #         print(f'Idemp: {my_idemp_true_rate}% True / {my_idemp_false_rate}% False, Lib: {lib_idemp_true_rate}% True / {lib_idemp_false_rate}% False')
    # enc_true_rate = enc_same / iters * 100
    # enc_false_rate = (1-(enc_same / iters)) * 100
    # dec_true_rate = dec_same / iters * 100
    # dec_false_rate = (1-(dec_same / iters)) * 100
    # my_idemp_true_rate = my_idemp / iters * 100
    # my_idemp_false_rate = (1-(my_idemp / iters)) * 100
    # lib_idemp_true_rate = lib_idemp / iters * 100
    # lib_idemp_false_rate = (1-(lib_idemp / iters)) * 100
    # print(f'100% Done! Enc: {enc_true_rate}% True / {enc_false_rate}% False, Dec: {dec_true_rate}% True / {dec_false_rate}% False')
    # print(f'Idemp: {my_idemp_true_rate}% True / {my_idemp_false_rate}% False, Lib: {lib_idemp_true_rate}% True / {lib_idemp_false_rate}% False')
    key = b'YELLOW SUBMARINE'
    iv = key
    phrase = b'YELLOW SUBMARINE'
    p_cookie = encrypt_aes_cbc(phrase, key, iv)
    lib_cookie = lib_enc_aes_cbc(phrase, key, iv)
    print(f'mine: {p_cookie}')
    print(f'lib:  {lib_cookie}')
    # if padding_oracle(p_cookie, key, iv):
    #     print(f'Cookie was padded correctly')
    # else:
    #     print(f'Cookie was somehow not padded correctly')
    # if padding_oracle(lib_cookie, key, iv):
    #     print(f'Lib cookie was padded correctly')
    # else:
    #     print(f'Lib cookie was somehow not padded correctly')
    lib_phrase = lib_dec_aes_cbc(p_cookie, key, iv)
    print(f'lib_phrase = {lib_phrase}')
    d_phrase = decrypt_aes_cbc(p_cookie, key, iv)
    print(f'd_phrase = {d_phrase}')
