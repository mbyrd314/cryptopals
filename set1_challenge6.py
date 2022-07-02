import string
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

def str2bytes(s):
    bytes = []
    for char in s:
        byte = format(ord(char), 'b')
        while len(byte) < 8:
            byte = '0' + byte
        bytes.append(byte)
    return bytes

def xor_byte(b1, b2):
    ans = ''
    for i in range(len(b1)):
        if b1[i] == b2[i]:
            ans += '0'
        else:
            ans += '1'
    return ans

def hamming_distance(s1_bytes, s2_bytes):
    # s1_bytes = str2bytes(s1)
    # s2_bytes = str2bytes(s2)
    total = 0
    #print('s1_bytes: %s' % str(s1_bytes))
    #print('s2_bytes: %s' % str(s2_bytes))
    #print('Len 1: %d, Len 2: %d' % (len(s1_bytes), len(s2_bytes)))
    for i in range(len(s1_bytes)):
        num = xor_byte(s1_bytes[i], s2_bytes[i])
        for bit in num:
            if bit == '1':
                total += 1
    return total

def find_keysize(s):
    min_distance = float('inf')
    keysize = None
    dists = []
    for i in range(2, 41):
        s1 = s[:8*i]
        s2 = s[8*i:2*8*i]
        s3 = s[2*8*i:3*8*i]
        s4 = s[3*8*i:4*8*i]
        if len(s1) != len(s2) or len(s2) != len(s3) or len(s3) != len(s4):
            break
        #print('s1: %s, s2: %s')
        #print('s1: %s' % str(s1))
        # #print('s2: %s' % str(s2))
        # dist1 = float(hamming_distance(s1, s2)) / float(i)
        # dist2 = float(hamming_distance(s1, s3)) / float(i)
        # dist3 = float(hamming_distance(s2, s3)) / float(i)
        # dist = (dist1 + dist2 + dist3) / 3
        s_list = [s1,s2,s3,s4]
        dist_sum = 0
        count = 0
        for j in range(len(s_list)):
            for k in range(j+1, len(s_list)):
                tmp_dist = float(hamming_distance(s_list[j], s_list[k])) / float(i)
                dist_sum += tmp_dist
                count += 1
        #print('Count: %d' % count)
        dist = dist_sum / float(count)
        #print('Keysize: %d, dist: %2f' % (i, dist))
        dists.append([dist, i])
        if dist < min_distance:
            min_distance = dist
            keysize = i
    dists.sort(key=lambda x: x[0])
    # print(dists)
    # print(dists[:3])
    # print(dists[0][1])
    # print('Min dist: %2f' % min_distance)
    # print('Keysize: %d' % keysize)
    ans = []
    for i in range(5):
        ans.append(dists[i][1])
    #print(ans)
    return ans

def get_blocks(bytes, keysize):
    blocks = []
    #print('Keysize: %d, Num_blocks: %d' % (keysize, len(bytes)//keysize))
    for i in range(len(bytes)//8//keysize):
        blocks.append(bytes[8*keysize*i:8*keysize*i+8*keysize])
    print('Length: %d, block_length: %d, bytes_length: %d' % (len(blocks), len(blocks[0]), len(bytes)))
    if len(bytes) % len(blocks[0]): # If there is not an integer number of bytes
        blocks.append(bytes[len(blocks)*len(blocks[0]) :])
    #for j in range(8*len(blocks[0]), len(bytes)):
    #for block in blocks[-2:]:
        #print('block_size: %d' % len(block))
    #print(blocks)

    return blocks

def split_blocks(blocks, keysize):
    ans = []
    for i in range(keysize):
        ans.append([])
        for block in blocks:
            if 8*i < len(block):
                ans[i].append(block[8*i:8*i+8])
        #print('i: %d, block_size: %d' % (i, len(ans[i])))
    print('Length(ans): %d, Length(ans[i]): %d' % (len(ans), len(ans[0])))
    return ans

# def dec_single_byte_xor(cyphertext):
#     cypherbytes = hex2bytes(cyphertext)
#     likely_list = list(range(97,122)) + [32]
#     best_total = 0
#     for key in range(255):
#         total = 0
#         keystring = format(key, 'b')
#         while len(keystring) < 8:
#             keystring = '0' + keystring
#         plain = ''
#         for i in range(len(cypherbytes)):
#             if cypherbytes[i] == keystring[i%8]:
#                 plain += '0'
#             else:
#                 plain += '1'
#         msg = ''
#         for i in range(len(plain)//8):
#             char = plain[8*i:8*i+8]
#             msg += chr(int(char,2))
#             if int(char, 2) in likely_list:
#                 total += 1
#         if total > best_total:
#             best_total = total
#             best_msg = msg
#             best_key = key
#     return best_total, best_key, best_msg

def dec_single_byte_xor(cypherbytes):
    #cypherbytes = hex2bytes(cyphertext)
    #likely_list = list(range(97,122)) + [32]
    #print('cypherbytes: %s' % cypherbytes)
    cypherbytes = ''.join(cypherbytes)
    #print('Length: %d' % len(cypherbytes))
    #print('cypherbytes: %s' % cypherbytes)
    cyphertext = bytes2hex(cypherbytes)
    #print('cyphertext: %s' % cyphertext)
    likely_list = list('etaoin shrdlcumwfgypbvkjxqz')
    likely_list.reverse()
    best_total = 0
    best_key = 0
    best_msg = ''
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
                total += .9*likely_list.index(c)**1.2 + 1
        #for c in plain:

        #print('key: %d' % key)
        #print('msg: %s' % msg)
        #print('total: %d' % total)
        if total > best_total:
            best_total = total
            best_msg = msg
            best_key = key
    return best_total, best_key, best_msg
    # print('Best total: %d' % best_total)
    # print('Best key: %d' % best_key)
    # print('Best message: %s' % best_msg)

def hex2base64(s):
    byteList = []
    for i in range(64):
        newBin = format(i, 'b')
        while len(newBin) < 6:
            newBin = '0' + newBin
        byteList.append(newBin)
    #print(byteList)
    charList = string.ascii_uppercase + string.ascii_lowercase
    for i in range(10):
        charList += str(i)
    charList += '+/'
    charList = list(charList)
    #print(charList)
    #print([key for key in byteList])
    #print([value for value in charList])
    #charDic = {key:value for key in byteList for value in charList}
    charDic = dict(zip(byteList, charList))
    #print(charDic)
    ans = ''
    for i in range(len(s)//6):
        char = s[6*i:6*i+6]
        ans += charDic[char]
        #print('char: %s' % char)
        #print('ans: %s' % ans)
    return ans

def base642hex(s):
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
    #print(f'charList: {charList}, byteList: {byteList}')
    # print([key for key in byteList])
    # print([value for value in charList])
    #charDic = {key:value for key in byteList for value in charList}
    charDic = dict(zip(charList, byteList))
    ans = ''
    for char in s:
        #char = s[6*i:6*i+6]
        if char in charDic:
            ans += charDic[char]
        else:
            l = len(ans)
            print('Length: %d' % l)
            diff = 8 - l % 8
            for i in range(diff):
                ans += '0'
            print('Length: %d' % len(ans))
            print('Char not decoded: %s' % char)
            #ans += ' '
        #print('char: %s' % char)
        #print('ans: %s' % ans)
    return ans

def dec_rep_key_xor(cyphertext):
    cypherbytes = base642hex(cyphertext)
    keysizes = find_keysize(cypherbytes)
    print('keysizes: %s' % str(keysizes))
    l = len(cypherbytes)
    best_block_sum = 0
    for keysize in keysizes:
        blocks = split_blocks(get_blocks(cypherbytes, keysize), keysize)
        ans = ''
        block_sum = 0
        keys = []
        msgs = []
        for block in blocks:
            #print('Block: %s' % str(block))
            #print('Length: %d' % len(block))
            total, key, msg = dec_single_byte_xor(block)
            block_sum += total
            keys.append(key)
            msgs.append(msg)
        # for i in range(len(msgs[0])):
        #     for msg in msgs:
        #         ans+=msg[i]
        full_key = ''.join([chr(key) for key in keys])
        full_msg = ''.join(msgs)
        print('keysize: %d, block_sum: %d, key: %s' % (keysize, block_sum, full_key))
        #print('msg: %s' % full_msg)

        if block_sum > best_block_sum:
            best_block_sum = block_sum
            best_keys = keys
            best_keysize = keysize
            best_msgs = msgs
    best_chars = ''.join([chr(key) for key in best_keys])
    best_block_size = l // best_keysize
    # print(type(l))
    # print(type(best_keysize))
    #print('cyphertext: %s' % cyphertext)
    print('best_keysize: %d' % best_keysize)
    # print(type(l))
    # print(type(best_keysize))
    print('best_block_size: %d' % best_block_size)
    print('l: %d' % l)
    print('best_keys: %s' % str(best_keys))
    print('best_chars: %s' % str(best_chars))
    #print('best_msgs: %s' % str(best_msgs))
    for i in range(len(best_msgs[0])):
        for msg in best_msgs:
            if i < len(msg):
                ans += msg[i]
    return ans

def hex_from_text(cyphertext):
    ans = ''
    byteList = []
    for i in range(16):
        newBin = format(i, 'b')
        while len(newBin) < 4:
            newBin = '0' + newBin
        byteList.append(newBin)
    charList = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']
    charDic = dict(zip(charList, byteList))
    for c in cyphertext:
        ans += charDic[c]
    print(f'cyphertext: {cyphertext}')
    print(f'ans: {ans}')
    return ans

def dec_rep_key_xor2(cyphertext):
    #cypherbytes = base642hex(cyphertext)
    cypherbytes = hex_from_text(cyphertext)
    #keysizes = find_keysize(cypherbytes)
    keysizes = [6]
    print('keysizes: %s' % str(keysizes))
    l = len(cypherbytes)
    best_block_sum = 0
    for keysize in keysizes:
        blocks = split_blocks(get_blocks(cypherbytes, keysize), keysize)
        ans = ''
        block_sum = 0
        keys = []
        msgs = []
        for block in blocks:
            #print('Block: %s' % str(block))
            #print('Length: %d' % len(block))
            total, key, msg = dec_single_byte_xor(block)
            block_sum += total
            keys.append(key)
            msgs.append(msg)
        # for i in range(len(msgs[0])):
        #     for msg in msgs:
        #         ans+=msg[i]
        full_key = ''.join([chr(key) for key in keys])
        full_msg = ''.join(msgs)
        print('keysize: %d, block_sum: %d, key: %s' % (keysize, block_sum, full_key))
        #print('msg: %s' % full_msg)

        if block_sum > best_block_sum:
            best_block_sum = block_sum
            best_keys = keys
            best_keysize = keysize
            best_msgs = msgs
    best_chars = ''.join([chr(key) for key in best_keys])
    best_block_size = l // best_keysize
    # print(type(l))
    # print(type(best_keysize))
    #print('cyphertext: %s' % cyphertext)
    print('best_keysize: %d' % best_keysize)
    # print(type(l))
    # print(type(best_keysize))
    print('best_block_size: %d' % best_block_size)
    print('l: %d' % l)
    print('best_keys: %s' % str(best_keys))
    print('best_chars: %s' % str(best_chars))
    #print('best_msgs: %s' % str(best_msgs))
    for i in range(len(best_msgs[0])):
        for msg in best_msgs:
            if i < len(msg):
                ans += msg[i]
    return ans


if __name__ == '__main__':
    # s1 = 'this is a test'
    # s2 = 'wokka wokka!!!'
    # print(hamming_distance(s1, s2))
    filename = 'set1_challenge6.txt'
    outfile = 'set1_challenge6_out.txt'
    # outlines = []
    # with open(filename, 'r') as f:
    #     lines = f.readlines()
    #     for line in lines:
    #         line = line[:-1]
    #         #print(line)
    #         #print('Length: %d' % len(line))
    #         ans = dec_rep_key_xor(line)
    #         outlines.append(ans)
    # print(outlines)
    # with open(outfile, 'w+') as f:
    #     for line in outlines:
    #         f.write(line + '\n')
    text = ''
    with open(filename, 'r') as f:
        lines = f.readlines()
        for line in lines:
            line = line[:-1]
            text += line
        ans = dec_rep_key_xor(text)
        #print(ans)
    new_ans = ''
    for i in range(len(ans)):
        if i % 60:
            new_ans += '\n'
        new_ans += ans[i]
    text2 = "7a032c24051f5c1e610713025c02223150024a4c2f3b5006561e24741109561935741304541c342015194a4c353c1105190d3220020457032c2d50024a4c20361f1e4d4c35311c0e4a0f2e24151817"
    ans2 = dec_rep_key_xor2(text2)
    print(f'ans2: {ans2}')
    with open(outfile, 'w') as f:
        f.write(new_ans)
