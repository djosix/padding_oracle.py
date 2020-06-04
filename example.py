'''
Boilerplate script for solving padding oracle challenges.
'''

from padding_oracle import *

import requests, string

# Create a requests.Session to enable connection pool
sess = requests.Session()

# Define a function to test if the cipher can be decrypted
def oracle(cipher: bytes):
    token = base64_encode(cipher)
    resp = sess.post('http://insucure.com/verify_token', data={'token': token})
    assert 'failed' in resp.text or 'success' in resp.text, 'exception???'
    return 'decryption failed' not in resp.text


# cipher = base64_decode(token)
cipher = b'[______IV______][____Block1____][____Block2____]'

# DECRYPT THE CIPHER!!!
plaintext = padding_oracle(cipher,
                           block_size=16,
                           oracle=oracle,
                           num_threads=16,
                           chars=string.printable)
