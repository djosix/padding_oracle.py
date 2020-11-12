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
from typing import Callable, Union, List, Optional, Generator, Tuple
from types import ModuleType
from queue import Empty as QueueEmpty
import multiprocessing.dummy

from .encoding import to_bytes


__all__ = [
    'Solver', 'solve',
    'remove_padding',
    'plaintext_list_to_bytes'
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


def plaintext_list_to_bytes(plaintext_list, unknown=b' '):
    plaintext_bytes = bytes(unknown if b is None else b
                            for b in plaintext_list)
    return plaintext_bytes


def solve(**kwargs):
    cipher = kwargs.pop('cipher')
    unknown = kwargs.pop('unknown', b' ')
    solver = Solver(**kwargs)
    plaintext = plaintext_list_to_bytes(solver.solve(cipher))
    plaintext = remove_padding(plaintext)
    return plaintext


class Solver:
    block_size: int = 16  # positive integer
    possible_bytes: bytes = bytes(range(256))  # bytes
    num_threads: int = 1  # positive integer
    validator: Optional[Callable[[bytes], bool]] = None # function(bytes) -> bool
    logger: logging.Logger = logging.getLogger(__name__)  # Logger
    mp: ModuleType = multiprocessing.dummy # thread-based, or `multiprocessing` for process-based

    def __init__(self,
                 block_size: int = None,
                 possible_bytes: bytes = None,
                 num_threads: int = None,
                 validator: Callable = None,
                 logger: logging.Logger = None,
                 mp: ModuleType = None):
        if block_size is not None:
            self.block_size = block_size
        if possible_bytes is not None:
            self.possible_bytes = possible_bytes
        if num_threads is not None:
            self.num_threads = num_threads
        if validator is not None:
            self.validator = validator
        if logger is not None:
            self.logger = logger
        if mp is not None:
            self.mp = mp

    def check_params(self):
        assert isinstance(self.block_size, int) and self.block_size > 0, (
            'block_size should be a positive integer')
        assert isinstance(self.possible_bytes,
                          bytes), 'possible_bytes should be bytes'
        assert isinstance(self.num_threads, int) and self.num_threads > 0, (
            'num_threads should be a positive integer')
        assert self.validator is not None and callable(self.validator), (
            'please implement the validator function')

    def oracle(self, validator):
        self.validator = validator

    def solve(self, cipher: bytes, unknown: bytes = b' ') -> List[Optional[int]]:
        plaintext_list = [None] * (len(cipher) - self.block_size)
        unknown = ord(unknown)

        for block_index, byte_index, byte in self.iter_solve(cipher):
            index = (block_index - 1) * self.block_size + byte_index
            plaintext_list[index] = byte

            self.logger.debug('decrypted list: {!r}'.format(plaintext_list))

            plaintext = bytes(
                unknown if b is None else b for b in plaintext_list)
            self.logger.info('decrypted: {!r}'.format(plaintext))

        return plaintext_list

    def iter_solve(self, cipher: bytes):
        # check cipher and divide cipher bytes into blocks
        assert len(cipher) % self.block_size == 0, (
            'invalid cipher length: {}'.format(len(cipher)))
        cipher_blocks = []
        for i in range(0, len(cipher), self.block_size):
            cipher_blocks.append(cipher[i:i + self.block_size])
        
        self.logger.debug('cipher blocks: {}'.format(cipher_blocks))

        # check other params
        self.check_params()

        possible_bytes = set(self.possible_bytes) | set(
            range(1, self.block_size + 1))
        
        self.logger.debug('creating pool and queue')
        
        pool = self.mp.Pool(self.num_threads)
        queue = self.mp.Queue()

        def _decrypt(block_index, block, prefix_bytes, queue):
            prefix_list = list(prefix_bytes)

            for n in range(1, self.block_size + 1):
                byte_index = self.block_size - n    # byte index in the block
                validate_results = {}               # async result handler for validator
                valid_bytes = []                    # valid try, expect only one item if vulnerable

                for p in possible_bytes:
                    b = p ^ n ^ prefix_bytes[-n]

                    if block_index == len(cipher_blocks) - 1 and n == 1 and b == prefix_bytes[-n]:
                        # skip the last padding byte if it is identical to the original cipher
                        continue

                    # modify prefix block and construct the cipher
                    test_prefix_list = prefix_list.copy()
                    test_prefix_list[-n] = b
                    test_cipher = bytes(test_prefix_list) + block

                    # add and run validation for constructed cipher
                    validate_results[b] = pool.apply_async(
                        self.validator, (test_cipher, ))

                has_exception_in_thread = False

                # collect valid bytes from validator results
                for b, result in validate_results.items():
                    is_valid = False
                    try:
                        is_valid = result.get()
                    except:
                        # catch exceptions generated in the thread
                        self.logger.error('at block {} pos {}, unhandled error in validator:\n{}'.format(
                            block_index, byte_index, traceback.format_exc()))
                        has_exception_in_thread = True
                    if is_valid:
                        valid_bytes.append(b)

                self.logger.debug('at block {} pos {}, valid bytes are {}'.format(
                    block_index, byte_index, valid_bytes))

                if len(valid_bytes) != 1:
                    # something goes wrong here, please check the validator
                    self.logger.error('at block {} pos {}, expect only one valid byte, got {}'.format(
                        block_index, byte_index, len(valid_bytes)))
                    return
                elif has_exception_in_thread:
                    self.logger.warning(
                        'at block {} pos {}, an exception was ignored')

                prefix_list[-n] = valid_bytes[0]
                for i in range(n):
                    prefix_list[-i-1] ^= n ^ (n + 1)

                decrypted = valid_bytes[0] ^ n ^ prefix_bytes[-n]

                self.logger.debug('at block {} pos {}, decrypted a byte {!r}'.format(
                    block_index, byte_index, bytes([decrypted])))

                queue.put((block_index, byte_index, decrypted))

        block_procs = []

        for i in reversed(range(1, len(cipher_blocks))):
            prefix_bytes = b''.join(cipher_blocks[:i])
            block = b''.join(cipher_blocks[i:i+1])

            self.logger.debug(
                'starting decryption process for block {}'.format(i))
            p = self.mp.Process(target=_decrypt, args=(
                i, block, prefix_bytes, queue))
            p.start()
            block_procs.append(p)

        while any(p.is_alive() for p in block_procs):
            try:
                yield queue.get(timeout=1)
            except QueueEmpty:
                continue

        self.logger.debug('shutting down pool and processes')

        for p in block_procs:
            p.join()

        pool.terminate()
        pool.join()

        self.logger.debug('end solving')

    def __repr__(self):
        return '<{}.{} (block_size={}, validator={}, num_threads={}, mp={}, logger={})>'.format(
            self.__module__, self.__class__.__qualname__,
            self.block_size, self.validator.__name__,
            self.num_threads, self.mp.__name__, self.logger)

    __str__ = __repr__
