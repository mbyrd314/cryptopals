import os, random

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

def PKCS_7_unpad(msg, block_size):
    """
    Undoes PKCS7 padding

    Args:
        msg (bytes): Message to be unpadded.

    Raises:
        ValueError: If message is not padded with PKCS#7, raises ValueError

    Returns:
        new_msg (bytes): Returns either the unpadded version of the original message
                         or the original message if not padded
    """
    if len(msg) % block_size:
        raise ValueError('Not padded')
    padding_size = msg[-1]
    # In case the message ends in a 0 byte, this prevents it from interpreting that
    # as a padding_size of 0 bytes
    if padding_size == 0:
        return msg
    #print('padding_size: %d' % padding_size)
    for i in range(len(msg)-1, len(msg)-padding_size-1, -1):
        if msg[i] != padding_size:
            raise ValueError('Not padded correctly')
            #print('No Padding')
            return msg
    #print('Padding Removed')
    new_msg = msg[:-padding_size]
    return new_msg


if __name__ == '__main__':
    """
    Main function to test the PKCS_validation function on various messages.

    If iter is high enough, there might be randomly generated messages with
    2 '2' bytes at the end, even though they weren't padded. The correct percentages
    might not be 100.
    """

    iter = 100000
    false_padded_count = 0
    false_unpadded_count = 0
    for i in range(iter):
        msg_length = random.randint(500, 5000)
        msg = os.urandom(msg_length)
        keysize = random.randint(16, 250)
        padded_msg = PKCS_7_pad(msg, keysize)
        try:
            unpadded_msg = PKCS_7_unpad(padded_msg, keysize)
            if unpadded_msg != msg:
                false_padded_count += 1
        except ValueError:
            print(f'padded_msg: {padded_msg}')
            false_padded_count += 1
        try:
            unpadded_msg = PKCS_7_unpad(msg, keysize)
            if unpadded_msg != msg:
                # Printing the final bytes of failed messages
                # They are 1s, because a final byte of 1 is indistinguishable from
                # valid PKCS#7 padding
                print(f'Failed unpadding: {msg[-1]}')
                false_unpadded_count += 1
        except ValueError:
            # These messages aren't padded, so they should throw ValueErrors
            pass
    true_padded_percentage = (iter-false_padded_count)/iter*100
    true_unpadded_percentage = (iter-false_unpadded_count)/iter*100
    print(f'{false_padded_count} Errors on Padded Messages')
    print(f'{true_padded_percentage}% Correct')
    print(f'{false_unpadded_count} Errors on Unpadded Messages')
    print(f'{true_unpadded_percentage}% Correct')
