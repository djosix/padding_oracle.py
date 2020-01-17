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
from typing import Union, Callable
from concurrent.futures import ThreadPoolExecutor

from .encoding import *

__all__ = [
    'padding_oracle',
    'remove_padding'
]


def remove_padding(data: Union[str, bytes]):
    data = _to_bytes(data)
    return data[:-data[-1]]


def _dummy_oracle(cipher: bytes) -> bool:
    raise NotImplementedError('You must implement the oracle function')


def padding_oracle(cipher: bytes,
                   block_size: int,
                   oracle: Callable[[bytes], bool] = _dummy_oracle,
                   num_threads: int = 1,
                   log_level: int = logging.INFO,
                   null: bytes = b' ') -> bytes:
    # Check the oracle function
    assert callable(oracle), 'the oracle function should be callable'
    assert oracle.__code__.co_argcount == 1, 'expect oracle function with only 1 argument'
    assert len(cipher) % block_size == 0, 'cipher length should be multiple of block size'

    logger = logging.getLogger('padding_oracle')
    logger.setLevel(log_level)
    formatter = logging.Formatter('[%(asctime)s][%(levelname)s] %(message)s')
    # formatter = logging.Formatter('[%(asctime)s][%(name)s][%(levelname)s] %(message)s')
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # The plaintext bytes list to save the decrypted data
    plaintext = [null] * (len(cipher) - block_size)

    def _update_plaintext(i: int, c: bytes):
        plaintext[i] = c
        logger.info('plaintext: {}'.format(b''.join(plaintext)))

    oracle_executor = ThreadPoolExecutor(max_workers=num_threads)

    def _block_decrypt_task(i, prev: bytes, block: bytes):
        logger.debug('task={} prev={} block={}'.format(i, prev, block))
        guess_list = list(prev)

        for j in range(1, block_size + 1):
            oracle_hits = []
            oracle_futures = {}

            for k in range(256):
                if i == len(blocks) - 1 and j == 1 and k == prev[-j]:
                    # skip the last padding byte if it is identical to the original cipher
                    continue

                test_list = guess_list.copy()
                test_list[-j] = k
                oracle_futures[k] = oracle_executor.submit(
                    oracle, bytes(test_list) + block)

            for k, future in oracle_futures.items():
                if future.result():
                    oracle_hits.append(k)

            logger.debug(
                'oracles at block[{}][{}] -> {}'.format(i, block_size - j, oracle_hits))

            if len(oracle_hits) != 1:
                logfmt = 'at block[{}][{}]: expect only one positive result, got {}. (skipped)'
                logger.error(logfmt.format(i, block_size-j, len(oracle_hits)))
                return

            guess_list[-j] = oracle_hits[0]

            p = guess_list[-j] ^ j ^ prev[-j]
            _update_plaintext(i * block_size - j, bytes([p]))

            for n in range(j):
                guess_list[-n-1] ^= j
                guess_list[-n-1] ^= j + 1

    blocks = []

    for i in range(0, len(cipher), block_size):
        j = i + block_size
        blocks.append(cipher[i:j])

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
