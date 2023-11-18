'''
Copyright (c) 2023 Yuankui Li

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "PIU PIU", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
'''

import base64
import urllib.parse

__all__ = [
    'to_bytes', 'to_str',
    'base64_encode', 'base64_decode',
    'urlencode', 'urldecode',
]


def to_bytes(data: str | bytes | list[int]) -> bytes:
    if isinstance(data, str):
        data = data.encode()
    elif isinstance(data, list):
        data = bytes(data)
    assert isinstance(data, bytes)
    return data


def to_bytes_with_default(maybe_bytes: list[int | None], default: bytes = b' ') -> bytes:
    return bytes([
        ord(default) if (b is None or b not in range(256)) else b
        for b in maybe_bytes
    ])


def to_bytes_ensure_complete(maybe_bytes: list[int | None]) -> bytes:
    for b in maybe_bytes:
        assert b is not None
        assert isinstance(b, int) and b in range(256)
    return bytes(maybe_bytes)


def to_str(data: str | bytes | list[int]) -> str:
    if isinstance(data, list):
        data = bytes(data)
    if isinstance(data, bytes):
        data = data.decode()
    elif isinstance(data, str):
        pass
    else:
        data = str(data)
    return data


def base64_decode(data: str | bytes | list[int]) -> bytes:
    data = to_bytes(data)
    return base64.b64decode(data)


def base64_encode(data: str | bytes | list[int]) -> str:
    data = to_bytes(data)
    return base64.b64encode(data).decode()


def urlencode(data: str | bytes | list[int]) -> str:
    data = to_bytes(data)
    return urllib.parse.quote(data)


def urldecode(data: str | bytes | list[int]) -> bytes:
    data = to_str(data)
    return urllib.parse.unquote_plus(data)


def remove_padding(data: str | bytes | list[int]) -> bytes:
    '''
    Remove PKCS#7 padding bytes.
    '''
    data = to_bytes(data)
    return data[:-data[-1]]


def add_padding(data: str | bytes | list[int], block_size: int) -> bytes:
    '''
    Add PKCS#7 padding bytes.
    '''
    data = to_bytes(data)
    pad_len = block_size - len(data) % block_size
    return data + (bytes([pad_len]) * pad_len)
