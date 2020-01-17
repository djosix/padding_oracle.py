from padding_oracle import *

import requests
sess = requests.Session()

def oracle(cipher):
    r = sess.post('http://some-website.com/decrypt', data={'cipher': base64_encode(cipher)})
    assert 'SUCCESS' in r.text or 'FAILED' in r.text
    return 'SUCCESS' in r.text

cipher = b'[      IV      ][    Block 1   ][    Block 2   ]'
plaintext = padding_oracle(cipher,  # cipher bytes      (required)
                           16,      # block size        (required)
                           oracle,  # oracle function   (required)
                           64)      # number of threads
