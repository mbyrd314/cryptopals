from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
from base64 import b64encode, b64decode

def decrypt_aes_ecb1(ciphertext, key):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    msg = decryptor.update(ciphertext) + decryptor.finalize()
    return msg

def decrypt_aes_ecb2(ciphertext, key):
    aes = AES.new(key, AES.MODE_ECB)
    msg = aes.decrypt(ciphertext)
    return msg

if __name__ == '__main__':
    with open('set1_challenge7.txt', 'r') as f:
        ciphertext = b64decode(f.read())
        key = b'YELLOW SUBMARINE'
        msg = decrypt_aes_ecb2(ciphertext, key)
        print(msg.decode())
