from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode
from binascii import hexlify, unhexlify

def decrypt_aes_ecb(ciphertext, key):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    msg = decryptor.update(ciphertext) + decryptor.finalize()
    return msg

if __name__ == '__main__':
    with open('set1_challenge8.txt') as f:
        lines = f.readlines()
        likely_list = list('etaoin shrdlcumwfgypbvkjxqz')
        likely_list.reverse()
        output = []
        best_total = 0
        for line in lines:
            print('line: %s' % line.strip())
            line = unhexlify(line.strip())
            print('decoded line: %s' % line)
            if len(line) % 16:
                print('Error: line not integer number of blocks')
            else:
                num_blocks = len(line) // 16
                blocks = [line[i*16:(i+1)*16] for i in range(num_blocks)]
                if len(set(blocks)) != num_blocks: # There is a duplicate
                    output.append(line)
            # for i in range(16):
            #     block = line[i:i+16]
            #     print(block)
            #     print('len: %d' % len(block))
            #     print('i: %d, index: %d' % (i, line.find(block)))
            #     if line.find(block) > i:
            #         key = bytes(block)
            # #key = b'YELLOW SUBMARINE'
            #         msg = decrypt_aes_ecb(line, key).decode()
            #         print(msg)
            #         total = 0
            #         for c in msg:
            #             if c in likely_list:
            #                 total += likely_list.index(c)
            #         if total >= best_total:
            #             best_total = total
            #             best_ctext = line
            #             best_msg = msg
        # print('Best ciphertext: %s' % best_ctext)
        # print('Best msg: %s' % best_msg)
        print('output: %s' % str(output))
