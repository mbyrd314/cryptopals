import string
# from base64 import b64decode, b64encode

def hex2base64(s):
    b = b''
    bIdx = 0
    newChar = 0
    hex_vals = b'0123456789abcdef'
    hex_dict = {hex_vals[i]:i for i in range(16)}
    b64_vals = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    b64_dict = {i:chr(b64_vals[i]).encode() for i in range(64)}
    # print(f'len(b64_vals)={len(b64_vals)}, len(b64_dict)={len(b64_dict)}')
    # print(f'b64_dict.keys()={b64_dict.keys()}')
    # print(f'b64_dict={b64_dict}')
    for c in s.lower():
        bits = hex_dict[c]
        # print(f'bIdx={bIdx}, c={c}, bits={bits}')
        if bIdx == 0:
            newChar ^= bits << 2
        else:
            newChar ^= (bits >> 2*(bIdx-1))
        prev = bIdx
        bIdx = (bIdx + 2) % 3
        if bIdx < prev: # next char
            b += b64_dict[newChar]
            if bIdx == 0:
                newChar = 0
            else:
                newChar = (bits & 3) << 4
        # print(f'b={b}, newChar={newChar}, newBits={bin(newChar)} bIdx={bIdx}, prev={prev}')
    b += b'=' * bIdx
    return b

def base642hex(b):
    s = b''
    # print(f'b={b}')
    hex_vals = b'0123456789abcdef'
    hex_dict = {i:chr(hex_vals[i]).encode() for i in range(16)}
    b64_vals = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    b64_dict = {b64_vals[i]:i for i in range(64)}
    # print(f'len(b64_vals)={len(b64_vals)}, len(b64_dict)={len(b64_dict)}')
    # print(f'b64_dict.keys()={b64_dict.keys()}')
    # print(f'b64_dict={b64_dict}')
    for i in range(len(b)//2):
        if b[2*i] == b'=':
            # print('Two Padding Chars')
            break
        bits = b64_dict[b[2*i]]
        # print(f'i={i}, b[2*i]={b[2*i]}={chr(b[2*i])}, bits={bits}')
        newChar = bits >> 2
        s += hex_dict[newChar]
        prevBits = (bits&3) << 2
        # print(f'newChar={newChar}, s={s}, prevBits={prevBits}')
        if b[2*i+1] == b'=':
            newChar = prevBits
            s += hex_dict[newChar]
            # print(f'One Padding Char')
            # print(f'newChar={newChar}, s={s}')
        else:
            newBits = b64_dict[b[2*i+1]]
            newChar = prevBits | (newBits >> 4)
            s += hex_dict[newChar]
            # print(f'newBits={newBits}, newChar={newChar}, s={s}')
            newChar = newBits & 15
            s += hex_dict[newChar]
        #     print(f'newChar={newChar}, s={s}')
        # print(f'End of Iteration: s={s}')
    return s

if __name__ == '__main__':
    test_str = b'49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    test_enc = hex2base64(test_str)
    print(f'test_str = {test_str}, test_enc = {test_enc}')
    # print(f'library = {b64encode(test_str)}')
    test_dec = base642hex(test_enc)
    print(f'test_str = {test_str}, test_enc = {test_enc}, test_dec = {test_dec}')
    print(test_str)
    print(test_dec)
    print(f'test_str==test_dec = {test_str==test_dec}')
