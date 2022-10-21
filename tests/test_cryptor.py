import os
from .cryptor import VulnerableCryptor

VERBOSE = False


def test_cryptor():
    for size in range(1, 128):
        cryptor = VulnerableCryptor()
        plaintext = os.urandom(size)
        if VERBOSE:
            print('test_cryptor', size, plaintext)
        ciphertext = cryptor.encrypt(plaintext)
        assert len(ciphertext) % cryptor.block_size == 0
        assert cryptor.decrypt(ciphertext) == plaintext, \
            f'{len(plaintext)} {len(ciphertext)}'


if __name__ == '__main__':
    VERBOSE = True
    test_cryptor()
