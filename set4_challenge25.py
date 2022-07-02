# Use the edit function on a newtext consisting of all null bytes
# Since the ciphertext is just MSG ^ KEY and the same key is used every time,
# you can xor two ciphertexts to get rid of the key
# (MSG1 ^ KEY) ^ (MSG2 ^ KEY) = MSG1 ^ MSG2
# With MSG1 being the plaintext that I want and MSG2 being under my control,
# it is simplest to use all null bytes for MSG2 so that the result is MSG1

'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff'

def edit(ciphertext, key, offset, newtext):
    out = ciphertext[:offset]
    keysize = len(key)
    ctr = offset // keysize
    key_bytes = int.to_bytes(0, 8, byteorder='little') + ctr.to_bytes(8, byteorder='little')
    keystream = encrypt_aes_ecb(key_bytes, key)
    for i in range(offset, offset+len(newtext)):
        idx = i % keysize
        if idx == 0:
            key_bytes = int.to_bytes(0, 8, byteorder='little') + ctr.to_bytes(8, byteorder='little')
            keystream = encrypt_aes_ecb(key_bytes, key)
            ctr += 1
        out += (msg[i] ^ keystream[idx]).to_bytes(1, byteorder='big')
    out += ciphertext[offset+len(newtext):]
    return out

if __name__ == '__main__':
    
