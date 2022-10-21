import logging
from padding_oracle import padding_oracle
from .cryptor import VulnerableCryptor

def test_padding_oracle_basic():
    cryptor = VulnerableCryptor()
    
    plaintext = b'the quick brown fox jumps over the lazy dog'
    ciphertext = cryptor.encrypt(plaintext)
    
    decrypted = padding_oracle(ciphertext, cryptor.block_size,
                               cryptor.oracle, 4, null_byte=b'?')
    print(decrypted)
    
    assert decrypted == plaintext
    
if __name__ == '__main__':
    test_padding_oracle_basic()
