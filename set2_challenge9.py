def PKCS_7_pad(msg, block_size):
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

if __name__ == '__main__':
    test_msg = b'YELLOW_SUBMARINE'
    b_msg = PKCS_7_pad(test_msg, 15)
    print(b_msg)
    print(len(b_msg))
