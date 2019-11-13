from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode
import os, random, string

def PKCS_7_pad(msg, block_size):
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
    padding_size = msg[-1]
    #print('padding_size: %d' % padding_size)
    for i in range(len(msg)-1, len(msg)-padding_size-1, -1):
        if msg[i] != padding_size:
            #print('No Padding')
            return msg
    #print('Padding Removed')
    new_msg = msg[:-padding_size]
    return new_msg

def decrypt_aes_ecb(ciphertext, key):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    msg = decryptor.update(ciphertext) + decryptor.finalize()
    return msg

def encrypt_aes_ecb(plaintext, key):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()
    cmsg = encryptor.update(plaintext) + encryptor.finalize()
    return cmsg

def test_enc_dec():
    key = b'YELLOW SUBMARINE'
    with open('set1_challenge7.txt', 'r') as f:
        ciphertext = b64decode(f.read())
        msg = decrypt_aes_ecb(ciphertext, key)
        #print(msg.decode())
        cmsg = encrypt_aes_ecb(msg, key)
        dmsg = decrypt_aes_ecb(cmsg, key)
        #print(dmsg.decode())

def xor_bytes(byte1, byte2):
    return bytes(a^b for a,b in zip(byte1, byte2))

def encrypt_aes_cbc(plaintext, key, iv):
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



if __name__ == '__main__':
    test_enc_dec()
    iters = 100
    for i in range(iters):
        length = random.randint(1000, 10000)
        msg = os.urandom(length)
        key = os.urandom(16)
        iv = os.urandom(16)
        assert(decrypt_aes_cbc(encrypt_aes_cbc(msg, key, iv), key, iv) == msg)
        # This should be working since there are no assertion errors on random msgs
        # with random keys and random ivs
        if not (i*10) % iters:
            x = (i*10) // iters
            print('%d Percent Done' % (x*10))
