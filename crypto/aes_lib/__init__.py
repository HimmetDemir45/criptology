"""Kütüphaneli AES-128 (cryptography paketi).

Güvenli modun varsayılan şifreleyicisidir ve kütüphanesiz AES'in çıktısıyla
karşılaştırma için referans olarak kullanılır.

Biçim: IV (16 byte) || AES-128-CBC(PKCS#7 dolgulu düz metin)
"""

import os

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher as _Cipher, algorithms, modes

from common.config import AES_BLOCK_SIZE, AES_KEY_SIZE
from crypto.cipher import Cipher


class LibraryAES(Cipher):
    name = "aes-lib"

    def __init__(self, key: bytes):
        if len(key) != AES_KEY_SIZE:
            raise ValueError(f"AES-128 anahtarı {AES_KEY_SIZE} byte olmalı, {len(key)} byte verildi")
        self.key = key

    def encrypt(self, plaintext: bytes) -> bytes:
        iv = os.urandom(AES_BLOCK_SIZE)
        padder = padding.PKCS7(AES_BLOCK_SIZE * 8).padder()
        padded = padder.update(plaintext) + padder.finalize()
        encryptor = _Cipher(algorithms.AES(self.key), modes.CBC(iv)).encryptor()
        return iv + encryptor.update(padded) + encryptor.finalize()

    def decrypt(self, data: bytes) -> bytes:
        if len(data) < 2 * AES_BLOCK_SIZE or len(data) % AES_BLOCK_SIZE:
            raise ValueError("Şifreli veri uzunluğu geçersiz")
        iv, ciphertext = data[:AES_BLOCK_SIZE], data[AES_BLOCK_SIZE:]
        decryptor = _Cipher(algorithms.AES(self.key), modes.CBC(iv)).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(AES_BLOCK_SIZE * 8).unpadder()
        return unpadder.update(padded) + unpadder.finalize()
