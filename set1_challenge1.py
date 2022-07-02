import string

def hex2bytes(s):
    ans = ''
    d = {'0': '0000', '1': '0001', '2': '0010', '3': '0011', '4': '0100',
        '5': '0101', '6': '0110', '7': '0111', '8': '1000', '9': '1001',
        'a': '1010', 'b': '1011', 'c': '1100', 'd': '1101', 'e': '1110',
        'f': '1111'}
    for c in s:
        ans += d[c]
        #print('c: %s' % c)
        #print('d: %s' % str(d))
    return ans

def hex2base64(s):
    byteList = []
    for i in range(64):
        newBin = format(i, 'b')
        while len(newBin) < 6:
            newBin = '0' + newBin
        byteList.append(newBin)
    print(byteList)
    charList = string.ascii_uppercase + string.ascii_lowercase
    for i in range(10):
        charList += str(i)
    charList += '+/'
    charList = list(charList)
    print(charList)
    print([key for key in byteList])
    print([value for value in charList])
    #charDic = {key:value for key in byteList for value in charList}
    charDic = dict(zip(byteList, charList))
    print(charDic)
    ans = ''
    for i in range(len(s)//6):
        char = s[6*i:6*i+6]
        ans += charDic[char]
        #print('char: %s' % char)
        #print('ans: %s' % ans)
    return ans

if __name__ == '__main__':
    print(hex2base64(hex2bytes('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')))
