from cryptography.hazmat.primitives import padding
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

def test_padding_oracle_encryption():
    cryptor = VulnerableCryptor()

    plaintext = b'the quick brown fox jumps over the lazy dog'
    ciphertext = cryptor.encrypt(plaintext)

    padder = padding.PKCS7(128).padder()
    payload = padder.update(plaintext) + padder.finalize()
    
    encrypted = padding_oracle(payload, cryptor.block_size,
                               cryptor.oracle, 4, null_byte=b'?', mode='encrypt')
    decrypted = cryptor.decrypt(encrypted)

    assert decrypted == plaintext

if __name__ == '__main__':
    test_padding_oracle_basic()
    test_padding_oracle_encryption()
