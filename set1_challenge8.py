from binascii import hexlify, unhexlify

if __name__ == '__main__':
    """
    Reads through all lines in the input text file to find the one encrypted with
    AES ECB mode. This can be detected by a duplicate block occurring when the
    same 16 byte plaintext string is encrypted twice.
    """
    with open('set1_challenge8.txt') as f:
        lines = f.readlines()
        for i, line in enumerate(lines):
            #print('line: %s' % line.strip())
            line = unhexlify(line.strip())
            #print('decoded line: %s' % line)
            if len(line) % 16:
                print('Error: line not integer number of blocks')
            else:
                num_blocks = len(line) // 16
                blocks = [line[i*16:(i+1)*16] for i in range(num_blocks)]
                if len(set(blocks)) != num_blocks: # There is a duplicate
                    ans_line = line
                    ans_num = i
        print(f'ans_num: {ans_num}, ans_line: {ans_line}')
