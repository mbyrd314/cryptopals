from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode
import os, random, string


def parse_cookie(cookie):
    """
    Takes inputs in the form of 'foo=bar&baz=qux' and converts them into a dictionary
    mapping keys to values. Assumes that the input strings are well-formed.

    Args:
        cookie (str): String consisting of key=value pairs separated by '&'

    Returns:
        ans {dict}: Dictionary mapping keys to values
    """
    ans = {}
    cookie = cookie.split(b'&')
    for pair in cookie:
        k, v = pair.split(b'=')
        ans[k] = v
    return ans

def profile_for(email):
    """
    Creates a user profile with the given email address. Encodes it in the key=value
    cookie format described in parse_cookie. Generates a uid and defaults to user
    level access for new profiles. Email strings are sanitized before encoding.

    Args:
        email (str): String email address to be encoded in a profile

    Returns:
        cookie (str): Formatted cookie representing the new profile
    """
    email = sanitize(email)
    uid = 10 # This hopefully wouldn't be fixed in a real implementation, but this could work for other uids
    role = 'user'
    cookie = f'email={email}&uid={uid}&role={role}'.encode()
    print(f'Making profile. cookie: {cookie}')
    return cookie

def encrypt_profile(email, key):
    profile = profile_for(email)
    return encrypt_aes_ecb(profile, key)

def decrypt_profile(ciphertext, key):
    """
    Does byte-at-a-time decryption of the encrypted profile using the functions
    written for the last challenge. Returns the parsed profile.

    Args:
        ciphertext (bytes): Encrypted profile to be decrypted

    Returns:
        (dict): Dictionary mapping profile keys to values
    """
    cookie = decrypt_aes_ecb(ciphertext, key)
    print(f'cookie: {cookie}')
    return parse_cookie(cookie)

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

def aes_keygen(keysize):
    """
    Generates a random key of length keysize

    Args:
        keysize (int): Length of the desired key in bytes

    Returns:
        (bytes): A generated key of length keysize
    """
    return os.urandom(keysize)

def sanitize(s):
    """
    Implements rudimentary input sanitization to prevent obvious injection flaws

    Args:
        s (str): String input to be sanitized

    Returns:
        ret (str): Sanitized version of the input string
    """
    ret = ''
    for c in s:
        if c not in ['&', '=']:
            ret += c
        else:
            ret += '_'
    return ret


if __name__ == '__main__':
    """
    Main function that will determine a ciphertext that will correctly correspond
    to a user with admin access.
    """
    key = aes_keygen(16)
    # Making an arbitrary email of the correct length so that the cookie string
    # email=test_email&uid=10&role= will end a block after role=. This will be the
    # prefix of the forged cookie.
    test_email = 'AAfoo@bar.com'
    test_ctext = encrypt_profile(test_email, key)
    # All but the last block of the ciphertext forms the prefix of the forged cookie
    prefix = test_ctext[:-16]
    # Forming another arbitrary email string. This time it needs to be the correct
    # length so that the word admin PKCS#7 padded to the block size will occur at
    # the beginning of a block.
    admin_email = b'oo@bar.com'
    admin_block = PKCS_7_pad(b'admin', 16)
    # Appending the padded admin string to the end of the email
    admin_email += admin_block
    admin_ctext = encrypt_profile(admin_email.decode(), key)
    # The ciphertext of admin padded to the block size is the second block
    admin_suffix = admin_ctext[16:32]
    # Forging a new valid ciphertext by appending the admin suffix to the prefix
    forged_profile_ctext = prefix + admin_suffix
    # Decrypting the forged profile to show that it does indeed have the role admin
    forged_profile = decrypt_profile(forged_profile_ctext, key)
    for k in forged_profile.keys():
        print(f'{k}: {forged_profile[k].decode()}')
