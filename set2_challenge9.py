import os
import random

def PKCS_7_pad(msg, block_size):
    """
    Implementation of PKCS7 padding

    Args:
        msg (bytes): Message to be padded
        block_size (bytes): Block size that the message needs to be padded to

    Returns:
        b_msg (bytes): PKCS padded version of the input message
    """
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

def PKCS_7_unpad(msg):
    """
    Undoes PKCS7 padding

    Args:
        msg (bytes): Message to be unpadded. If not padded with PKCS7, returns the original message

    Returns:
        new_msg (bytes): Returns either the unpadded version of the original message
                         or the original message if not padded
    """
    padding_size = msg[-1]
    #print('padding_size: %d' % padding_size)
    for i in range(len(msg)-1, len(msg)-padding_size-1, -1):
        if msg[i] != padding_size:
            #print('No Padding')
            return msg
    #print('Padding Removed')
    new_msg = msg[:-padding_size]
    return new_msg

if __name__ == '__main__':
    """
    Tests that the PKCS7 padding function produces the correct padded message
    and that the unpadding function correctly removes the padding and returns the
    original message for random messages of random lengths with random block sizes.
    """
    test_msg = b'YELLOW_SUBMARINE'
    b_msg = PKCS_7_pad(test_msg, 17)
    print(b_msg)
    print(len(b_msg))
    iters = 100
    # Testing that the padding and unpadding work on lots of random messages
    for i in range(iters):
        msg_length = random.randint(7, 10000007)
        block_size = random.randint(10, 255)
        msg = os.urandom(msg_length)
        assert(PKCS_7_unpad(PKCS_7_pad(msg, block_size))==msg)
        if not (i*10) % iters:
            x = (i*10) // iters
            print('%d Percent Done' % (x*10))
