# padding_oracle.py

Extremely fast threaded [padding oracle](http://server.maojui.me/Crypto/Padding_oracle_attack/) automation script for Python 3.

## Install

Installing from PyPI:

```shell
pip3 install -U padding_oracle
```

Or, installing from GitHub:

```shell
pip3 install -U git+https://github.com/djosix/padding_oracle.py.git
```

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

```
