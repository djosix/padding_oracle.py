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

import time, requests
from padding_oracle import *  # also provide url encoding and base64 functions

sess = requests.Session()

cipher = b'[______IV______][____Cipher____]'  # decrypted plain text will be 16 bytes
block_size = 16

@padding_oracle(cipher, block_size, num_threads=64)
def oracle(cipher):   # return True if the cipher can be correctly decrypted
    while True:
        try:
            text = sess.get('https://example.com/decrypt',
                            params={'cipher': base64_encode(cipher)}).text
            assert 'YES' in text or 'NO' in text  # check if the request failed
            break
        except:
            print('[!] request failed')
            time.sleep(1)
            continue
    return 'YES' in text

print(oracle)   # b'FLAG{XXXXXXXX}\x02\x02'
```
