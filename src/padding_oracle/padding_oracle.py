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

import os
import threading
import traceback
import functools
from typing import Callable

from .solve import solve, OracleFunc, BlockResult
from .logger import Logger, default_logger
from .utils import to_bytes, to_bytes_with_default, to_bytes_ensure_complete, add_padding


__all__ = [
    'decrypt',
    'encrypt'
]


def decrypt(
    ciphertext: bytes | str,
    block_size: int,
    oracle: OracleFunc,
    num_threads: int = 1,
    logger: Logger = default_logger,
) -> bytes:

    ciphertext = to_bytes(ciphertext)
    assert len(ciphertext) % block_size == 0, 'ciphertext length must be a multiple of block size'

    oracle = with_exception_logger(oracle, logger)

    result = solve(
        ciphertext,
        block_size,
        oracle,
        num_threads,
        block_error_logger(logger),
        decrypt_progress_logger(logger),
    )
    return to_bytes_ensure_complete(result)


def encrypt(
    plaintext: bytes | str,
    block_size: int,
    oracle: OracleFunc,
    num_threads: int = 1,
    logger: Logger = default_logger,
) -> bytes:
    plaintext = to_bytes(plaintext)
    plaintext = add_padding(plaintext, block_size)

    oracle = with_exception_logger(oracle, logger)

    plain_blocks = [plaintext[i:i+block_size] for i in range(0, len(plaintext), block_size)]
    cipher_blocks = [os.urandom(block_size)]  # in reverse order

    for i in range(len(plain_blocks)):
        iv = os.urandom(block_size)
        result = solve(
            iv + cipher_blocks[i],
            block_size,
            oracle,
            num_threads,
            block_error_logger(logger),
            encrypt_progress_logger(logger, i+1, len(plain_blocks)),
        )
        previous_cipher_block = bytes([
            b1 ^ b2 ^ b3
            for b1, b2, b3 in zip(
                iv,
                to_bytes_ensure_complete(result),
                plain_blocks[len(plain_blocks)-i-1],
            )
        ])
        cipher_blocks.append(previous_cipher_block)

    return b''.join(reversed(cipher_blocks))


def with_exception_logger(oracle: OracleFunc, logger: Logger) -> OracleFunc:
    lock = threading.Lock()

    @functools.wraps(oracle)
    def wrapped(payload: bytes) -> bool:
        try:
            return oracle(payload)
        except Exception as e:
            lock.acquire()  # make sure these logs are not interleaved
            logger('oracle_error', f'payload={payload!r} error={str(e)!r}')
            logger('oracle_error_trace', '\n' + traceback.format_exc())
        finally:
            if lock.locked():
                lock.release()

        return False

    return wrapped


def block_error_logger(logger: Logger) -> Callable[[BlockResult], None]:
    def callback(result: BlockResult):
        if result.error is not None:
            logger('solve_block_error', result.error)
    return callback


def decrypt_progress_logger(logger: Logger, unknown_byte: bytes = b' ') -> Callable[[bytes], None]:
    def callback(incomplete_plaintext: list[int | None]):
        logger('progress', f'{to_bytes_with_default(incomplete_plaintext, unknown_byte)!r}')
    return callback


def encrypt_progress_logger(logger: Logger, blocks_done: int, blocks_total: int) -> Callable[[list[int | None]], None]:
    def callback(incomplete_ciphertext: list[int | None]):
        bytes_done = sum(1 for b in incomplete_ciphertext if b is not None)
        bytes_total = len(incomplete_ciphertext)
        logger('progress', f'block {blocks_done}/{blocks_total} encrypted {bytes_done}/{bytes_total} bytes')
    return callback
