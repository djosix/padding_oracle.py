'''
Copyright (c) 2022 Yuankui Li

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
from typing import List, Union

__all__ = [
    'base64_encode', 'base64_decode',
    'urlencode', 'urldecode',
    'to_bytes', 'to_str'
]


def to_bytes(data: Union[str, bytes, List[int]]) -> bytes:
    if isinstance(data, str):
        data = data.encode()
    elif isinstance(data, list):
        data = bytes(data)
    assert isinstance(data, bytes)
    return data


def to_str(data: Union[str, bytes, List[int]]) -> str:
    if isinstance(data, list):
        data = bytes(data)
    if isinstance(data, bytes):
        data = data.decode()
    elif isinstance(data, str):
        pass
    else:
        data = str(data)
    return data


def base64_decode(data: Union[str, bytes, List[int]]) -> bytes:
    data = to_bytes(data)
    return base64.b64decode(data)


def base64_encode(data: Union[str, bytes, List[int]]) -> str:
    data = to_bytes(data)
    return base64.b64encode(data).decode()


def urlencode(data: Union[str, bytes, List[int]]) -> str:
    data = to_bytes(data)
    return urllib.parse.quote(data)


def urldecode(data: Union[str, bytes, List[int]]) -> bytes:
    data = to_str(data)
    return urllib.parse.unquote_plus(data)
