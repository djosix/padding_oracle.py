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
    convert_to_bytes, remove_padding, add_padding)

__all__ = [
    'padding_oracle',
]

def padding_oracle(payload: Union[bytes, str],
                   block_size: int,
                   oracle: OracleFunc,
                   num_threads: int = 1,
                   log_level: int = logging.INFO,
                   null_byte: bytes = b' ',
                   return_raw: bool = False,
                   mode: Union[bool, str] = 'decrypt',
                   pad_payload: bool = True
                   ) -> Union[bytes, List[int]]:
    '''
    Run padding oracle attack to decrypt ciphertext given a function to check
    wether the ciphertext can be decrypted successfully.

    Args:
        payload        (bytes|str) the payload you want to encrypt/decrypt
        block_size     (int)       block size (the ciphertext length should be
                                   multiple of this)
        oracle         (function)  a function: oracle(ciphertext: bytes) -> bool
        num_threads    (int)       how many oracle functions will be run in
                                   parallel (default: 1)
        log_level      (int)       log level (default: logging.INFO)
        null_byte      (bytes|str) the default byte when plaintext are not
                                   set (default: None)
        return_raw     (bool)      do not convert plaintext into bytes and
                                   unpad (default: False)
        mode           (str)       encrypt the payload (defaut: 'decrypt')
        pad_payload    (bool)      PKCS#7 pad the supplied payload before
                                   encryption (default: True)


    Returns:
        result (bytes|List[int]) the processed payload
    '''

    # Check args
    if not callable(oracle):
        raise TypeError('the oracle function should be callable')
    if not isinstance(payload, (bytes, str)):
        raise TypeError('payload should have type bytes')
    if not isinstance(block_size, int):
        raise TypeError('block_size should have type int')
    if not 1 <= num_threads <= 1000:
        raise ValueError('num_threads should be in [1, 1000]')
    if not isinstance(null_byte, (bytes, str)):
        raise TypeError('expect null with type bytes or str')
    if not len(null_byte) == 1:
        raise ValueError('null byte should have length of 1')
    if not isinstance(mode, str):
        raise TypeError('expect mode with type str')
    if isinstance(mode, str) and mode not in ('encrypt', 'decrypt'):
        raise ValueError('mode must be either encrypt or decrypt')
    if (mode == 'decrypt') and not (len(payload) % block_size == 0):
        raise ValueError('for decryption payload length should be multiple of block size')
    logger = get_logger()
    logger.setLevel(log_level)

    payload = to_bytes(payload)
    null_byte = to_bytes(null_byte)


    # Does the user want the encryption routine
    if (mode == 'encrypt'):
        return encrypt(payload, block_size, oracle, num_threads, null_byte, pad_payload, logger)

    # If not continue with decryption as normal
    return decrypt(payload, block_size, oracle, num_threads, null_byte, return_raw, logger)

def decrypt(payload, block_size, oracle, num_threads, null_byte, return_raw, logger):
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

    plaintext = solve(payload, block_size, wrapped_oracle, num_threads,
                      result_callback, plaintext_callback)

    if not return_raw:
        plaintext = convert_to_bytes(plaintext, null_byte)
        plaintext = remove_padding(plaintext)

    return plaintext


def encrypt(payload, block_size, oracle, num_threads, null_byte, pad_payload, logger):
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
        plaintext = convert_to_bytes(plaintext, null_byte).strip(null_byte)
        bytes_done = str(len(plaintext)).rjust(len(str(block_size)), ' ')
        blocks_done = solve_index.rjust(len(block_total), ' ')
        printout = "{0}/{1} bytes encrypted in block {2}/{3}".format(bytes_done, block_size, blocks_done, block_total)
        logger.info(printout)

    def blocks(data: bytes):
        return [data[index:(index+block_size)] for index in range(0, len(data), block_size)]

    def bytes_xor(byte_string_1: bytes, byte_string_2: bytes):
        return bytes([_a ^ _b for _a, _b in zip(byte_string_1, byte_string_2)])

    if pad_payload:
        payload = add_padding(payload, block_size)

    if len(payload) % block_size != 0:
        raise ValueError('''For encryption payload length must be a multiple of blocksize. Perhaps you meant to
        pad the payload (inbuilt PKCS#7 padding can be enabled by setting pad_payload=True)''')

    plaintext_blocks = blocks(payload)
    ciphertext_blocks = [null_byte * block_size for _ in range(len(plaintext_blocks)+1)]
    
    solve_index = '1'
    block_total = str(len(plaintext_blocks))

    for index in range(len(plaintext_blocks)-1, -1, -1):
        plaintext = solve(b'\x00' * block_size + ciphertext_blocks[index+1], block_size, wrapped_oracle,
                            num_threads, result_callback, plaintext_callback)
        ciphertext_blocks[index] = bytes_xor(plaintext_blocks[index], plaintext)
        solve_index = str(int(solve_index)+1)
    
    ciphertext = b''.join(ciphertext_blocks)
    logger.info(f"forged ciphertext: {ciphertext}")

    return ciphertext

def get_logger():
    logger = logging.getLogger('padding_oracle')
    formatter = logging.Formatter('[%(asctime)s][%(levelname)s] %(message)s')
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger
