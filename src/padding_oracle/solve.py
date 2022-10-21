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
from typing import Any, Callable, NamedTuple, Set, Union, List

from .encoding import to_bytes


__all__ = [
    'solve',
    'convert_to_bytes',
    'remove_padding',
]

class Pass(NamedTuple):
    block_index: int
    index: int
    byte: int

class Fail(NamedTuple):
    block_index: int
    message: str
    is_critical: bool = False

class Done(NamedTuple):
    block_index: int
    C0: List[int]
    X1: List[int]


ResultType = Union[Pass, Fail, Done]

OracleFunc = Callable[[bytes], bool]
ResultCallback = Callable[[ResultType], bool]
PlainTextCallback = Callable[[List[int]], bool]
 

class Context(NamedTuple):
    block_size: int
    oracle: OracleFunc
    
    executor: ThreadPoolExecutor 
    loop: asyncio.AbstractEventLoop
    
    tasks: Set[asyncio.Task[ResultType]]

    latest_plaintext: List[int]
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

    loop = asyncio.get_event_loop()
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
    assert len(ciphertext) % block_size == 0, \
        'ciphertext length must be a multiple of block_size'
    assert len(ciphertext) // block_size > 1, \
        'cannot solve with only one block'

    ctx = create_solve_context(ciphertext, block_size, oracle, parallel,
                               result_callback, plaintext_callback)

    while True:
        done_tasks, _ = await asyncio.wait(ctx.tasks, return_when=asyncio.FIRST_COMPLETED)
        
        for task in done_tasks:
            result = await task
            
            ctx.result_callback(result)
            ctx.tasks.remove(task)
            
            if isinstance(result, Pass):
                update_latest_plaintext(ctx, result.block_index, result.index, result.byte)
            if isinstance(result, Done):
                update_plaintext(ctx, result.block_index, result.C0, result.X1)
        
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

    plaintext = [None] * (len(cipher_blocks) - 1) * block_size
    latest_plaintext = plaintext.copy()
    
    executor = ThreadPoolExecutor(parallel)
    loop = asyncio.get_running_loop()
    ctx = Context(block_size, oracle, executor, loop, tasks,
                  latest_plaintext, plaintext,
                  result_callback, plaintext_callback)
    
    for i in range(1, len(cipher_blocks)):
        run_block_task(ctx, i, cipher_blocks[i-1], cipher_blocks[i], [])

    return ctx

def run_block_task(ctx: Context, block_index, C0, C1, X1):
    future = solve_block(ctx, block_index, C0, C1, X1)
    task = ctx.loop.create_task(future)
    ctx.tasks.add(task)

async def solve_block(
    ctx: Context,
    block_index: int,
    C0: List[int],
    C1: List[int],
    X1: List[int] = [],
) -> ResultType:
    # X1 = decrypt(C1)
    # P1 = xor(C0, X1)

    if len(X1) == ctx.block_size:
        return Done(block_index, C0, X1)

    assert len(C0) == ctx.block_size
    assert len(C1) == ctx.block_size
    assert len(X1) in range(ctx.block_size)

    index = ctx.block_size - len(X1) - 1
    padding = len(X1) + 1

    C0_test = C0.copy()
    for i in range(len(X1)):
        C0_test[-i-1] = X1[-i-1] ^ padding
    hits = list(await get_oracle_hits(ctx, C0_test, C1, index))

    invalid = len(X1) == 0 and len(hits) not in (1, 2)
    invalid |= len(X1) > 0 and len(hits) != 1
    if invalid:
        message = 'unexpected number of hits: block={} index={} n={}' \
            .format(block_index, index, len(hits))
        return Fail(block_index, message)

    for byte in hits:
        X1_test = [byte ^ padding, *X1]
        run_block_task(ctx, block_index, C0, C1, X1_test)
        
    return Pass(block_index, index, byte ^ padding ^ C0[index])

async def get_oracle_hits(ctx: Context, C0: List[int], C1: List[int], index: int):
    
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

def update_latest_plaintext(ctx: Context, block_index: int, index: int, byte: int):
    i = (block_index - 1) * ctx.block_size + index
    ctx.latest_plaintext[i] = byte
    ctx.plaintext_callback(ctx.latest_plaintext)

def update_plaintext(ctx: Context, block_index: int, C0: List[int], X1: List[int]):
    assert len(C0) == len(X1) == ctx.block_size
    block = compute_plaintext(C0, X1)
    
    i = (block_index - 1) * ctx.block_size
    ctx.latest_plaintext[i:i+ctx.block_size] = block
    ctx.plaintext[i:i+ctx.block_size] = block
    ctx.plaintext_callback(ctx.plaintext)

def compute_plaintext(C0: List[int], X1: List[int]):
    return [c ^ x for c, x in zip(C0, X1)]

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
