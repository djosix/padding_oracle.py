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

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
'''

from .padding_oracle import (
    decrypt,
    encrypt,
)
from .utils import (
    to_bytes,
    to_str,
    base64_encode,
    base64_decode,
    urlencode,
    urldecode,
    remove_padding,
    add_padding,
)
from .logger import Logger, default_logger, nop_logger
from .solve import solve

__all__ = [
    'decrypt',
    'encrypt',
    'to_bytes',
    'to_str',
    'base64_encode',
    'base64_decode',
    'urlencode',
    'urldecode',
    'remove_padding',
    'add_padding',
    'solve',
    'Logger',
    'default_logger',
    'nop_logger',
]
