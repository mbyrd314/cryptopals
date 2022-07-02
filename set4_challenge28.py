# SHA1(key || message)
import os, cryptography
from cryptography.hazmat.primitives import hashes, hmac

# This isn't actually right. I should implement SHA-1 myself and use the dumb
# secret-prefix MAC instead of HMAC

def left_rotate(msg, shift):
    return ((msg << shift) | (msg >> (32-shift))) & (0xFFFFFFFF)

def sha1(msg):
    # print(f'SHA-1: Hashing {msg}')
    MAX_VAL = 0xFFFFFFFF
    h0 = int.from_bytes(b'\x67\x45\x23\x01', byteorder='big')
    h1 = int.from_bytes(b'\xEF\xCD\xAB\x89', byteorder='big')
    h2 = int.from_bytes(b'\x98\xBA\xDC\xFE', byteorder='big')
    h3 = int.from_bytes(b'\x10\x32\x54\x76', byteorder='big')
    h4 = int.from_bytes(b'\xC3\xD2\xE1\xF0', byteorder='big')
    # print('Original Vals:')
    # print(f'h0={h0}')
    # print(f'h1={h1}')
    # print(f'h2={h2}')
    # print(f'h3={h3}')
    # print(f'h4={h4}')
    ml = len(msg)*8 # Length of msg in bits

    pad_size = -(ml + 1 + 64) % 512
    padded_msg = msg + b'\x80' + b'\x00'*(pad_size//8) + ml.to_bytes(8, byteorder='big')
    # print(f'padded_msg={padded_msg}')
    # print(f'pad_size={pad_size}, Length={len(padded_msg)}')

    for i in range(len(padded_msg)//64):
        # print(f'i={i}')
        chunk = padded_msg[64*i:64*(i+1)]
        # print(f'chunk={chunk}')
        w = []
        for j in range(16):
            new_word_bytes = chunk[4*j:4*(j+1)]
            new_word = int.from_bytes(new_word_bytes, byteorder='big')
            w.append(new_word)
            # print(f'j={j}, new_word_bytes={new_word_bytes}, new_word={new_word}')
        # w = [int.from_bytes(chunk[4*k:4*(k+1)], byteorder='big') for k in range(16)]

        for j in range(16, 80):
            new_word = left_rotate(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1)
            w.append(new_word)
        # print(f'w={w}')
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
    # print('Final Vals:')
    # print(f'h0={h0}')
    # print(f'h1={h1}')
    # print(f'h2={h2}')
    # print(f'h3={h3}')
    # print(f'h4={h4}')
    hh = (h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32) | h4
    return hh

def secret_prefix_auth(key, msg):
    # print(f'Secret Prefix Auth: Hashing {key+msg}')
    return sha1(key+msg)



def authenticate_sha1(msg, signature, key):
    h = hmac.HMAC(key, hashes.SHA1())
    h.update(msg)
    try:
        h.verify(signature)
        return True
    except cryptography.exceptions.InvalidSignature:
        return False

def sign_sha1(msg, key):
    h = hmac.HMAC(key, hashes.SHA1())
    h.update(msg)
    return h.finalize()

if __name__ == '__main__':
    key = os.urandom(16)
    msg = b'TEST MESSAGE TO BE AUTHENTICATED'
    # signature = sign_sha1(msg, key)
    # valid = authenticate_sha1(msg, signature, key)
    # invalid = authenticate_sha1(msg, b'wrong signature', key)
    # print(f'valid = {valid}')
    # print(f'invalid = {invalid}')
    sig = sha1(msg)
    sig_bytes = sig.to_bytes(20, byteorder='big')
    print(f'msg={msg}')
    print(f'sig={sig}')
    print(f'sig_bytes={sig_bytes}')
    hash = secret_prefix_auth(key, msg)
    print(f'hash={hash}')
    hash_bytes = hash.to_bytes(20, byteorder='big')
    print(f'hash_bytes={hash_bytes}')
    other_hash = secret_prefix_auth(key, b'other message')
    other_hash_bytes = other_hash.to_bytes(20, byteorder='big')
    print(f'other hash={other_hash}')
    print(f'other_hash_bytes={other_hash_bytes}')
    print(f'hash_len={len(hash_bytes)}, other_len={len(other_hash_bytes)}')
