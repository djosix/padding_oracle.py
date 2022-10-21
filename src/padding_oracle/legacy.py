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

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
'''

import logging
import traceback
from typing import List, Union

from .encoding import to_bytes
from .solve import (
    solve, Fail, OracleFunc, ResultType,
    convert_to_bytes, remove_padding)

__all__ = [
    'padding_oracle',
]


def padding_oracle(ciphertext: Union[bytes, str],
                   block_size: int,
                   oracle: OracleFunc,
                   num_threads: int = 1,
                   log_level: int = logging.INFO,
                   null_byte: bytes = b' ',
                   return_raw: bool = False,
                   ) -> Union[bytes, List[int]]:
    '''
    Run padding oracle attack to decrypt ciphertext given a function to check
    wether the ciphertext can be decrypted successfully.

    Args:
        cipher         (bytes|str) the cipher you want to decrypt
        block_size     (int)       block size (the cipher length should be
                                   multiple of this)
        oracle         (function)  a function: oracle(cipher: bytes) -> bool
        num_threads    (int)       how many oracle functions will be run in
                                   parallel (default: 1)
        log_level      (int)       log level (default: logging.INFO)
        null_byte      (bytes|str) the default byte when plaintext are not
                                   set (default: None)
        return_raw     (bool)      do not convert plaintext into bytes and
                                   unpad (default: False)

    Returns:
        plaintext (bytes|List[int]) the decrypted plaintext
    '''

    # Check args
    if not callable(oracle):
        raise TypeError('the oracle function should be callable')
    if not isinstance(ciphertext, (bytes, str)):
        raise TypeError('cipher should have type bytes')
    if not isinstance(block_size, int):
        raise TypeError('block_size should have type int')
    if not len(ciphertext) % block_size == 0:
        raise ValueError('cipher length should be multiple of block size')
    if not 1 <= num_threads <= 1000:
        raise ValueError('num_threads should be in [1, 1000]')
    if not isinstance(null_byte, (bytes, str)):
        raise TypeError('expect null with type bytes or str')
    if not len(null_byte) == 1:
        raise ValueError('null byte should have length of 1')

    logger = get_logger()
    logger.setLevel(log_level)

    ciphertext = to_bytes(ciphertext)
    null_byte = to_bytes(null_byte)

    # Wrapper to handle exceptions from the oracle function
    def wrapped_oracle(ciphertext: bytes):
        try:
            return oracle(ciphertext)
        except Exception as e:
            logger.error(f'error in oracle with {ciphertext!r}, {e}')
            logger.debug('error details: {}'.format(traceback.format_exc()))
        return False

    def result_callback(result: ResultType):
        if isinstance(result, Fail):
            if result.is_critical:
                logger.critical(result.message)
            else:
                logger.error(result.message)

    def plaintext_callback(plaintext: bytes):
        plaintext = convert_to_bytes(plaintext, null_byte)
        logger.info(f'plaintext: {plaintext}')

    plaintext = solve(ciphertext, block_size, wrapped_oracle, num_threads,
                      result_callback, plaintext_callback)

    if not return_raw:
        plaintext = convert_to_bytes(plaintext, null_byte)
        plaintext = remove_padding(plaintext)

    return plaintext


def get_logger():
    logger = logging.getLogger('padding_oracle')
    formatter = logging.Formatter('[%(asctime)s][%(levelname)s] %(message)s')
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger
