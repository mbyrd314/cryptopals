from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
from base64 import b64encode, b64decode

def decrypt_aes_ecb1(ciphertext, key):
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

def decrypt_aes_ecb2(ciphertext, key):
    """
    Implementation of AES ECB mode decryption using the Python Crypto library

    Args:
        ciphertext (bytes): The ciphertext message to be decrypted
        key (bytes): The AES secret key

    Returns:
        msg (bytes): The decrypted version of the ciphertext input
    """
    aes = AES.new(key, AES.MODE_ECB)
    msg = aes.decrypt(ciphertext)
    return msg

if __name__ == '__main__':
    """
    Tests both of the above AES ECB mode decryption functions on the encrypted
    text file with known key.
    """
    with open('set1_challenge7.txt', 'r') as f:
        ciphertext = b64decode(f.read())
        key = b'YELLOW SUBMARINE'
        msg = decrypt_aes_ecb1(ciphertext, key)
        print(msg.decode())
        assert(decrypt_aes_ecb1(ciphertext, key)==decrypt_aes_ecb2(ciphertext,key))
