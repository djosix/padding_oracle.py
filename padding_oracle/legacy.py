'''
Copyright (c) 2020 Yuankui Lee

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
from typing import Union, Callable
from concurrent.futures import ThreadPoolExecutor

from .encoding import to_bytes

__all__ = [
    'padding_oracle',
    'remove_padding'
]


def remove_padding(data: Union[str, bytes]):
    '''
    Remove PKCS#7 padding bytes.

    Args:
        data (str | bytes)

    Returns:
        data with padding removed (bytes)
    '''
    data = to_bytes(data)
    return data[:-data[-1]]


def _get_logger():
    logger = logging.getLogger('padding_oracle')
    formatter = logging.Formatter('[%(asctime)s][%(levelname)s] %(message)s')
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


def padding_oracle(cipher: bytes,
                   block_size: int,
                   oracle: Callable[[bytes], bool],
                   num_threads: int = 1,
                   log_level: int = logging.INFO,
                   chars=None,
                   null: bytes = b' ') -> bytes:
    '''
    Run padding oracle attack to decrypt cipher given a function to check wether the cipher
    can be decrypted successfully.

    Args:
        cipher      (bytes|str) the cipher you want to decrypt
        block_size  (int)       block size (the cipher length should be multiple of this)
        oracle      (function)  a function: oracle(cipher: bytes) -> bool
        num_threads (int)       how many oracle functions will be run in parallel (default: 1)
        log_level   (int)       log level (default: logging.INFO)
        chars       (bytes|str) possible characters in your plaintext, None for all
        null        (bytes|str) the default byte when plaintext are not set (default: b' ')

    Returns:
        plaintext   (bytes)     the decrypted plaintext
    '''

    # Check args
    assert callable(oracle), 'the oracle function should be callable'
    assert oracle.__code__.co_argcount == 1, 'expect oracle function with only 1 argument'
    assert isinstance(cipher, (bytes, str)), 'cipher should have type bytes'
    assert isinstance(block_size, int), 'block_size should have type int'
    assert len(cipher) % block_size == 0, 'cipher length should be multiple of block size'
    assert 1 <= num_threads <= 1000, 'num_threads should be in [1, 1000]'
    assert isinstance(null, (bytes, str)), 'expect null with type bytes or str'
    assert len(null) == 1, 'null byte should have length of 1'
    assert isinstance(chars, (bytes, str)) or chars is None, 'chars should be None or type bytes'

    logger = _get_logger()
    logger.setLevel(log_level)
    
    cipher = to_bytes(cipher)
    null = to_bytes(null)
    
    if chars is None:
        chars = set(range(256))
    else:
        chars = set(to_bytes(chars))
        chars |= set(range(1, block_size + 1)) # include PCKS#7 padding bytes

    # Wrapper to handle exception from the oracle function
    def _oracle_wrapper(i: int, j: int, cipher: bytes):
        try:
            return oracle(cipher)
        except Exception as e:
            logger.error('unhandled error at block[{}][{}]: {}'.format(i, j, e))
            logger.debug('error details at block[{}][{}]: {}'.format(i, j, traceback.format_exc()))
        return False

    # The plaintext bytes list to store the decrypted data
    plaintext = [null] * (len(cipher) - block_size)

    # Update the decrypted plaintext list
    def _update_plaintext(i: int, c: bytes):
        plaintext[i] = c
        logger.info('plaintext: {}'.format(b''.join(plaintext)))

    oracle_executor = ThreadPoolExecutor(max_workers=num_threads)

    # Block decrypting task to be run in parallel
    def _block_decrypt_task(i, prev: bytes, block: bytes):
        logger.debug('task={} prev={} block={}'.format(i, prev, block))
        guess_list = list(prev)

        for j in range(1, block_size + 1):
            oracle_hits = []
            oracle_futures = {}

            for c in chars:
                k = c ^ j ^ prev[-j]
                
                if i == len(blocks) - 1 and j == 1 and k == prev[-j]:
                    # skip the last padding byte if it is identical to the original cipher
                    continue

                test_list = guess_list.copy()
                test_list[-j] = k
                oracle_futures[k] = oracle_executor.submit(
                    _oracle_wrapper, i, j, bytes(test_list) + block)

            for k, future in oracle_futures.items():
                if future.result():
                    oracle_hits.append(k)

            logger.debug(
                'oracles at block[{}][{}] -> {}'.format(i, block_size - j, oracle_hits))

            # Number of oracle hits should be 1, or we just ignore this block
            if len(oracle_hits) != 1:
                logfmt = 'at block[{}][{}]: expect only one hit, got {}. (skipped)'
                logger.error(logfmt.format(i, block_size-j, len(oracle_hits)))
                return

            guess_list[-j] = oracle_hits[0]

            p = guess_list[-j] ^ j ^ prev[-j]
            _update_plaintext(i * block_size - j, bytes([p]))

            for n in range(j):
                guess_list[-n-1] ^= j ^ (j + 1)

    blocks = []

    for i in range(0, len(cipher), block_size):
        blocks.append(cipher[i:i + block_size])

    logger.debug('blocks: {}'.format(blocks))

    with ThreadPoolExecutor() as executor:
        futures = []
        for i in reversed(range(1, len(blocks))):
            prev = b''.join(blocks[:i])
            block = b''.join(blocks[i:i+1])
            futures.append(executor.submit(_block_decrypt_task, i, prev, block))
        for future in futures:
            future.result()

    oracle_executor.shutdown()

    return b''.join(plaintext)
