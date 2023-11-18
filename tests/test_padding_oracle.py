from padding_oracle import decrypt, encrypt, remove_padding
from .cryptor import VulnerableCryptor


def test_padding_oracle_decrypt():
    plaintext = b'the quick brown fox jumps over the lazy dog'

    cryptor = VulnerableCryptor()
    ciphertext = cryptor.encrypt(plaintext)

    decrypted = decrypt(
        ciphertext,
        cryptor.block_size,
        cryptor.oracle,
        num_threads=4,
    )

    assert remove_padding(decrypted) == plaintext


def test_padding_oracle_encrypt():
    plaintext = b'the quick brown fox jumps over the lazy dog'

    cryptor = VulnerableCryptor()

    encrypted = encrypt(
        plaintext,
        cryptor.block_size,
        cryptor.oracle,
        num_threads=4,
    )

    assert cryptor.decrypt(encrypted) == plaintext


if __name__ == '__main__':
    test_padding_oracle_decrypt()
    test_padding_oracle_encrypt()
