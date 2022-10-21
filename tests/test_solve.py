from concurrent.futures import ProcessPoolExecutor
import os
import multiprocessing as mp

from padding_oracle import remove_padding
from padding_oracle.solve import solve
from .cryptor import VulnerableCryptor

VERBOSE = False

def _test_solve(data_size):
    crypter = VulnerableCryptor()
    
    plaintext = os.urandom(data_size)
    ciphertext = crypter.encrypt(plaintext)
    
    decrypted = solve(list(ciphertext), crypter.block_size, crypter.oracle)
    decrypted = remove_padding(decrypted)
    
    assert plaintext == decrypted, 'decryption failed'

def test_solve_basic():
    sizes = [0, 1, 15, 16, 17]
    for size in sizes:
        if VERBOSE:
            print('test_solve_basic', size)
        _test_solve(size)
        
def test_solve_many_sizes():
    with ProcessPoolExecutor(mp.cpu_count()) as executor:
        futures = []
        for size in [*range(0, 64, 7), *range(64, 128, 13)]:
            futures.append((size, executor.submit(_test_solve, size)))
        for size, future in futures:
            if VERBOSE:
                print('test_solve_many_sizes', size)
            future.result()

def test_solve_random_15():
    size = 15
    with ProcessPoolExecutor(mp.cpu_count()) as executor:
        futures = [executor.submit(_test_solve, size) for _ in range(64)]
        for future in futures:
            if VERBOSE:
                print('test_solve_random_15', size)
            future.result()

if __name__ == '__main__':
    VERBOSE = True
    test_solve_basic()
    test_solve_many_sizes()
    test_solve_random_15()
