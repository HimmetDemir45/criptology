"""Kütüphanesiz AES-128 — Yunus Özkan.

Yapılacaklar (README > Görev Dağılımı):
- S-box / ters S-box, SubBytes, ShiftRows, MixColumns (GF(2^8)), AddRoundKey
- Anahtar genişletme (11 tur anahtarı), 10 tur, şifre çözme
- CBC + rastgele IV, PKCS#7 dolgu
- FIPS-197 test vektörleriyle doğrulama

ManualAES sınıfı crypto.cipher.Cipher arayüzünü uygulamalı ve LibraryAES ile
aynı biçimi kullanmalıdır: IV (16 byte) || şifreli metin. Böylece sunucu ve
istemcide `--aes manual` seçildiğinde başka hiçbir kodu değiştirmek gerekmez.
"""

from crypto.cipher import Cipher


class ManualAES(Cipher):
    name = "aes-manual"

    def __init__(self, key: bytes):
        raise NotImplementedError("Kütüphanesiz AES henüz eklenmedi")

    def encrypt(self, plaintext: bytes) -> bytes:
        raise NotImplementedError

    def decrypt(self, data: bytes) -> bytes:
        raise NotImplementedError
