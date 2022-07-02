def hex2bytes(s):
    ans = ''
    d = {'0': '0000', '1': '0001', '2': '0010', '3': '0011', '4': '0100',
        '5': '0101', '6': '0110', '7': '0111', '8': '1000', '9': '1001',
        'a': '1010', 'b': '1011', 'c': '1100', 'd': '1101', 'e': '1110',
        'f': '1111'}
    for c in s:
        ans += d[c]
    return ans

def bytes2hex(bytes):
    ans = ''
    d = {'0': '0000', '1': '0001', '2': '0010', '3': '0011', '4': '0100',
        '5': '0101', '6': '0110', '7': '0111', '8': '1000', '9': '1001',
        'a': '1010', 'b': '1011', 'c': '1100', 'd': '1101', 'e': '1110',
        'f': '1111'}
    new_d = dict(zip(d.values(), d.keys()))
    for i in range(len(bytes)//4):
        char = bytes[4*i: 4*i+4]
        ans += new_d[char]
    return ans

def xor_byte(b1, b2):
    ans = ''
    for i in range(len(b1)):
        if b1[i] == b2[i]:
            ans += '0'
        else:
            ans += '1'
    return ans

def rep_key_xor(key, plaintext):
    keybytes = []
    plainbytes = []
    for char in key:
        keybyte = format(ord(char), 'b')
        while len(keybyte) < 8:
            keybyte = '0' + keybyte
        keybytes.append(keybyte)
    for char in plaintext:
        plainbyte = format(ord(char), 'b')
        while len(plainbyte) < 8:
            plainbyte = '0' + plainbyte
        plainbytes.append(plainbyte)
    # keybytes = hex2bytes(f'{key:02x}')
    # plainbytes = hex2bytes(plaintext)

    cypherbytes = ''
    for i in range(len(plaintext)):
        cypherbytes += xor_byte(keybytes[i%len(key)], plainbytes[i])
    cypherhex = bytes2hex(cypherbytes)
    return cypherhex
    # cyphertext = ''
    # for i in range(len(cypherbytes)//8):
    #     byte = cypherbytes[8*i:8*i+8]
    #     cyphertext += chr(int(byte,2))
    # return cyphertext


if __name__ == '__main__':
    test_str = 'Burning \'em, if you ain\'t quick and nimble\nI go crazy when I hear a cymbal'
    print(rep_key_xor('ICE', test_str))
