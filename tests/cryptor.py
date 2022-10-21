import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


class VulnerableCryptor:
    def __init__(self):
        self.block_size = 16
        self.key = os.urandom(16)
        self.padding = padding.PKCS7(128)

    def encrypt(self, plaintext):
        padder = self.padding.padder()
        plaintext = padder.update(plaintext) + padder.finalize()

        iv = os.urandom(self.block_size)
        encryptor = Cipher(algorithms.AES(self.key), modes.CBC(iv)).encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        return iv + ciphertext

    def decrypt(self, ciphertext):
        iv = ciphertext[:self.block_size]
        ciphertext = ciphertext[self.block_size:]

        decryptor = Cipher(algorithms.AES(self.key), modes.CBC(iv)).decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = self.padding.unpadder()
        unpadded = unpadder.update(plaintext) + unpadder.finalize()

        return unpadded

    def oracle(self, data):
        try:
            self.decrypt(data)
            return True
        except Exception:
            return False
