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
    Optional,
    Awaitable, Callable,
    NamedTuple,
    cast,
)

__all__ = [
    'solve',
]


class BlockResult:
    def __init__(
        self,
        block_index: int,
        *,
        solved: list[int | None] | None = None,
        error: None | str = None,
    ):
        self.block_index = block_index
        self.solved = solved
        self.error = error


OracleFunc = Callable[[bytes], bool]


class Context(NamedTuple):
    block_size: int
    oracle: OracleFunc

    executor: ThreadPoolExecutor
    loop: asyncio.AbstractEventLoop

    tasks: set[Awaitable[BlockResult]]

    solved_counts: dict[int, int]
    plaintext: list[int | None]

    block_callback: Callable[[BlockResult], None]
    progress_callback: Callable[[list[int | None]], None]


def solve(
    ciphertext: bytes,
    block_size: int,
    oracle: OracleFunc,
    num_threads: int,
    block_callback: Callable[[BlockResult], None],
    progress_callback: Callable[[list[int | None]], None],
) -> list[int | None]:

    loop = asyncio.new_event_loop()
    future = solve_async(
        ciphertext,
        block_size,
        oracle,
        num_threads,
        block_callback,
        progress_callback,
    )

    return loop.run_until_complete(future)


async def solve_async(
    ciphertext: bytes,
    block_size: int,
    oracle: OracleFunc,
    num_threads: int,
    block_callback: Callable[[BlockResult], None],
    progess_callback: Callable[[list[int | None]], None],
) -> list[int | None]:

    ciphertext = list(ciphertext)
    assert len(ciphertext) % block_size == 0
    assert len(ciphertext) // block_size > 1

    ctx = create_solve_context(
        ciphertext,
        block_size,
        oracle,
        num_threads,
        block_callback,
        progess_callback,
    )

    while True:
        done_tasks, _ = await asyncio.wait(
            ctx.tasks,
            return_when=asyncio.FIRST_COMPLETED,
        )

        for task in cast(set[Awaitable[BlockResult]], done_tasks):
            result = await task

            ctx.block_callback(result)
            ctx.tasks.remove(task)

            if result.solved is None:
                continue

            if len(result.solved) > ctx.solved_counts[result.block_index]:
                update_solved(ctx, result.block_index, result.solved)
                ctx.solved_counts[result.block_index] = len(result.solved)
                ctx.progress_callback(ctx.plaintext)

        if len(ctx.tasks) == 0:
            break

    # Check if any block failed.
    error_block_indices = set()

    for i, byte in enumerate(ctx.plaintext):
        if byte is None:
            error_block_indices.add(i // block_size + 1)

    for idx in error_block_indices:
        block_callback(BlockResult(idx, error=f'block {idx} not solved'))

    return list[int | None](ctx.plaintext)


def create_solve_context(
    ciphertext: bytes,
    block_size: int,
    oracle: OracleFunc,
    num_threads: int,
    block_callback: Callable[[BlockResult], None],
    progress_callback: Callable[[list[int | None]], None],
) -> Context:
    tasks = set()

    cipher_blocks = []
    for i in range(0, len(ciphertext), block_size):
        cipher_blocks.append(ciphertext[i:i+block_size])

    solved_counts = defaultdict(lambda: 0)

    plaintext = [None] * (len(cipher_blocks) - 1) * block_size

    executor = ThreadPoolExecutor(num_threads)
    loop = asyncio.get_event_loop()
    ctx = Context(
        block_size,
        oracle,
        executor,
        loop,
        tasks,
        solved_counts,
        plaintext,
        block_callback,
        progress_callback,
    )

    for i in range(len(cipher_blocks)-1):
        add_solve_block_task(ctx, i+1, cipher_blocks[i], cipher_blocks[i+1], [])

    return ctx


def add_solve_block_task(ctx: Context, block_index: int, C0: list[int],
                         C1: list[int], X1_suffix: list[int]):
    future = solve_block(ctx, block_index, C0, C1, X1_suffix)
    task = ctx.loop.create_task(future)
    ctx.tasks.add(task)


async def solve_block(ctx: Context, block_index: int, C0: list[int],
                      C1: list[int], X1_suffix: list[int] = []) -> BlockResult:

    assert len(C0) == ctx.block_size
    assert len(C1) == ctx.block_size
    assert len(X1_suffix) in range(ctx.block_size + 1)

    # X1 = decrypt(C1)
    # P1 = xor(C0, X1)
    C0_suffix = C0[len(C0)-len(X1_suffix):]
    P1_suffix = [c ^ x for c, x in zip(C0_suffix, X1_suffix)]

    if len(P1_suffix) < ctx.block_size:
        result = await exploit_oracle(ctx, block_index, C0, C1, X1_suffix)
        if result is not None and result.error is not None:
            return result

    return BlockResult(block_index, solved=P1_suffix)


async def exploit_oracle(ctx: Context, block_index: int,
                         C0: list[int], C1: list[int],
                         X1_suffix: list[int]) -> Optional[BlockResult]:
    index = ctx.block_size - len(X1_suffix) - 1
    padding = len(X1_suffix) + 1

    C0_test = C0.copy()
    for i in range(len(X1_suffix)):
        C0_test[-i-1] = X1_suffix[-i-1] ^ padding
    hits = list(await get_oracle_hits(ctx, C0_test, C1, index))

    # Check if the number of hits is invalid.
    invalid = len(X1_suffix) == 0 and len(hits) not in (1, 2)
    invalid |= len(X1_suffix) > 0 and len(hits) != 1
    if invalid:
        message = f'invalid number of hits: {len(hits)} (block: {block_index}, byte: {index})'
        return BlockResult(block_index, error=message)

    for byte in hits:
        X1_test = [byte ^ padding, *X1_suffix]
        add_solve_block_task(ctx, block_index, C0, C1, X1_test)


async def get_oracle_hits(
    ctx: Context,
    C0: list[int],
    C1: list[int],
    index: int,
) -> list[int]:

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


def update_solved(ctx: Context, block_index: int, solved_suffix: list[int]):
    j = block_index * ctx.block_size
    i = j - len(solved_suffix)
    ctx.plaintext[i:j] = solved_suffix
