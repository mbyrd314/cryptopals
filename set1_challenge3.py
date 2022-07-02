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

def dec_single_byte_xor(cyphertext):
    cypherbytes = hex2bytes(cyphertext)
    likely_list = list(range(97,122)) + [32]
    best_total = 0
    for key in range(255):
        total = 0
        keystring = format(key, 'b')
        while len(keystring) < 8:
            keystring = '0' + keystring
        plain = ''
        for i in range(len(cypherbytes)):
            if cypherbytes[i] == keystring[i%8]:
                plain += '0'
            else:
                plain += '1'
        msg = ''
        for i in range(len(plain)//8):
            char = plain[8*i:8*i+8]
            msg += chr(int(char,2))
            if int(char, 2) in likely_list:
                total += 1
        if total > best_total:
            best_total = total
            best_msg = msg
            best_key = key
    print('Best total: %d' % best_total)
    print('Best key: %d' % best_key)
    print('Best message: %s' % best_msg)

if __name__ == '__main__':
    dec_single_byte_xor('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
