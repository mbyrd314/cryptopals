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

def fixed_xor(s1, s2):
    s1_bytes = hex2bytes(s1)
    s2_bytes = hex2bytes(s2)
    s = ''
    for i in range(len(s1_bytes)):
        if s1_bytes[i] == s2_bytes[i]:
            s += '0'
        else:
            s += '1'
    return bytes2hex(s)

if __name__ == '__main__':
    print(fixed_xor('1c0111001f010100061a024b53535009181c', '686974207468652062756c6c277320657965'))
