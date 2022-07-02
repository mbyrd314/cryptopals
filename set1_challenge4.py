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
    #likely_list = list(range(97,122)) + [32]
    likely_list = list('etaoin shrdlcumwfgypbvkjxqz')
    likely_list.reverse()
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
            c = chr(int(char,2)).lower()
            if c in likely_list:
                total += .5 * likely_list.index(c)**2
        if total > best_total:
            best_total = total
            best_msg = msg
            best_key = key
    return best_total, best_key, best_msg
    # print('Best total: %d' % best_total)
    # print('Best key: %d' % best_key)
    # print('Best message: %s' % best_msg)

def find_encoded_string(filename):
    with open(filename, 'r') as f:
        lines = f.readlines()
        max_total = 0
        for line in lines:
            line = line[:-1]
            total, key, msg = dec_single_byte_xor(line)
            if total > max_total:
                max_total = total
                max_key = key
                max_msg = msg
    print('Max total: %d' % max_total)
    print('Max key: %d' % max_key)
    print('Max msg: %s' % max_msg)

if __name__ == '__main__':
    find_encoded_string('set1_challenge4.txt')
