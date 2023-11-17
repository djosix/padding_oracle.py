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

import asyncio
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
from typing import (
    Optional, Union,
    Awaitable, Callable,
    NamedTuple, List, Dict, Set,
)

from .encoding import to_bytes


__all__ = [
    'solve',
    'convert_to_bytes',
    'remove_padding',
    'add_padding'
]


class Pass(NamedTuple):
    block_index: int
    solved: List[int]


class Fail(NamedTuple):
    block_index: int
    message: str
    is_critical: bool = False


ResultType = Union[Pass, Fail]

OracleFunc = Callable[[bytes], bool]
ResultCallback = Callable[[ResultType], bool]
PlainTextCallback = Callable[[List[int]], bool]


class Context(NamedTuple):
    block_size: int
    oracle: OracleFunc

    executor: ThreadPoolExecutor
    loop: asyncio.AbstractEventLoop

    tasks: Set[Awaitable[ResultType]]

    solved_counts: Dict[int, int]
    plaintext: List[int]

    result_callback: ResultCallback
    plaintext_callback: PlainTextCallback


def dummy_callback(*a, **ka):
    pass


def solve(ciphertext: bytes,
          block_size: int,
          oracle: OracleFunc,
          parallel: int = 1,
          result_callback: ResultCallback = dummy_callback,
          plaintext_callback: PlainTextCallback = dummy_callback,
          ) -> List[int]:

    loop = asyncio.new_event_loop()
    future = solve_async(ciphertext, block_size, oracle, parallel,
                         result_callback, plaintext_callback)
    return loop.run_until_complete(future)


async def solve_async(ciphertext: bytes,
                      block_size: int,
                      oracle: OracleFunc,
                      parallel: int = 1,
                      result_callback: ResultCallback = dummy_callback,
                      plaintext_callback: PlainTextCallback = dummy_callback,
                      ) -> List[int]:

    ciphertext = list(ciphertext)

    if not len(ciphertext) % block_size == 0:
        raise ValueError('ciphertext length must be a multiple of block_size')
    if not len(ciphertext) // block_size > 1:
        raise ValueError('cannot solve with only one block')

    ctx = create_solve_context(ciphertext, block_size, oracle, parallel,
                               result_callback, plaintext_callback)

    while True:
        done_tasks, _ = await asyncio.wait(ctx.tasks,
                                           return_when=asyncio.FIRST_COMPLETED)

        for task in done_tasks:
            result = await task

            ctx.result_callback(result)
            ctx.tasks.remove(task)

            if isinstance(result, Pass):
                if len(result.solved) >= ctx.solved_counts[result.block_index]:
                    update_plaintext(ctx, result.block_index, result.solved)
                    ctx.solved_counts[result.block_index] = len(result.solved)
                    ctx.plaintext_callback(ctx.plaintext)

        if len(ctx.tasks) == 0:
            break

    # Check if any block failed
    error_block_indices = set()

    for i, byte in enumerate(ctx.plaintext):
        if byte is None:
            error_block_indices.add(i // block_size + 1)

    for idx in error_block_indices:
        result_callback(Fail(idx, f'cannot decrypt cipher block {idx}', True))

    return ctx.plaintext


def create_solve_context(ciphertext, block_size, oracle, parallel,
                         result_callback, plaintext_callback) -> Context:
    tasks = set()

    cipher_blocks = []
    for i in range(0, len(ciphertext), block_size):
        cipher_blocks.append(ciphertext[i:i+block_size])

    solved_counts = defaultdict(lambda: 0)

    plaintext = [None] * (len(cipher_blocks) - 1) * block_size

    executor = ThreadPoolExecutor(parallel)
    loop = asyncio.get_event_loop()
    ctx = Context(block_size, oracle, executor, loop, tasks,
                  solved_counts, plaintext,
                  result_callback, plaintext_callback)

    for i in range(1, len(cipher_blocks)):
        add_solve_block_task(ctx, i, cipher_blocks[i-1], cipher_blocks[i], [])

    return ctx


def add_solve_block_task(ctx: Context, block_index: int, C0: List[int],
                         C1: List[int], X1_suffix: List[int]):
    future = solve_block(ctx, block_index, C0, C1, X1_suffix)
    task = ctx.loop.create_task(future)
    ctx.tasks.add(task)


async def solve_block(ctx: Context, block_index: int, C0: List[int],
                      C1: List[int], X1_suffix: List[int] = []) -> ResultType:

    assert len(C0) == ctx.block_size
    assert len(C1) == ctx.block_size
    assert len(X1_suffix) in range(ctx.block_size + 1)

    # X1 = decrypt(C1)
    # P1 = xor(C0, X1)
    C0_suffix = C0[len(C0)-len(X1_suffix):]
    P1_suffix = [c ^ x for c, x in zip(C0_suffix, X1_suffix)]

    if len(P1_suffix) < ctx.block_size:
        result = await exploit_oracle(ctx, block_index, C0, C1, X1_suffix)
        if isinstance(result, Fail):
            return result

    return Pass(block_index, P1_suffix)


async def exploit_oracle(ctx: Context, block_index: int,
                         C0: List[int], C1: List[int],
                         X1_suffix: List[int]) -> Optional[Fail]:
    index = ctx.block_size - len(X1_suffix) - 1
    padding = len(X1_suffix) + 1

    C0_test = C0.copy()
    for i in range(len(X1_suffix)):
        C0_test[-i-1] = X1_suffix[-i-1] ^ padding
    hits = list(await get_oracle_hits(ctx, C0_test, C1, index))

    # Check if the number of hits is invalid
    invalid = len(X1_suffix) == 0 and len(hits) not in (1, 2)
    invalid |= len(X1_suffix) > 0 and len(hits) != 1
    if invalid:
        message = f'invalid number of hits: {len(hits)}'
        message = f'{message} (block: {block_index}, byte: {index})'
        return Fail(block_index, message)

    for byte in hits:
        X1_test = [byte ^ padding, *X1_suffix]
        add_solve_block_task(ctx, block_index, C0, C1, X1_test)


async def get_oracle_hits(ctx: Context, C0: List[int], C1: List[int],
                          index: int):

    C0 = C0.copy()
    futures = {}

    for byte in range(256):
        C0[index] = byte
        ciphertext = bytes(C0 + C1)
        futures[byte] = ctx.loop.run_in_executor(
            ctx.executor, ctx.oracle, ciphertext)

    hits = []

    for byte, future in futures.items():
        is_valid = await future
        if is_valid:
            hits.append(byte)

    return hits


def update_plaintext(ctx: Context, block_index: int, solved_suffix: List[int]):
    j = block_index * ctx.block_size
    i = j - len(solved_suffix)
    ctx.plaintext[i:j] = solved_suffix


def convert_to_bytes(byte_list: List[int], replacement=b' '):
    '''
    Convert a list of int into bytes, replace invalid byte with replacement.
    '''
    for i, byte in enumerate(list(byte_list)):
        if isinstance(byte, int) and byte in range(256):
            pass
        elif isinstance(byte, bytes):
            byte = ord(byte)
        else:
            byte = ord(replacement)
        byte_list[i] = byte
    return bytes(byte_list)


def remove_padding(data: Union[str, bytes, List[int]]) -> bytes:
    '''
    Remove PKCS#7 padding bytes.
    '''
    data = to_bytes(data)
    return data[:-data[-1]]


def add_padding(data: Union[str, bytes, List[int]], block_size: int) -> bytes:
    '''
    Add PKCS#7 padding bytes.
    '''
    data = to_bytes(data)
    pad_len = block_size - len(data) % block_size
    return data + (bytes([pad_len]) * pad_len)
