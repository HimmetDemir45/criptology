"""Veri şifreleme için ortak arayüz.

Sunucu ve istemci, verinin hangi AES gerçeklemesiyle (kütüphaneli / kütüphanesiz)
şifrelendiğini bilmez; sadece bu arayüzü kullanır.
"""

from abc import ABC, abstractmethod


class Cipher(ABC):
    name = ""

    @abstractmethod
    def encrypt(self, plaintext: bytes) -> bytes:
        """Düz metni şifreler. Dönen değer karşı tarafın çözmesi için gereken her şeyi
        (ör. IV + şifreli metin) içermelidir."""

    @abstractmethod
    def decrypt(self, data: bytes) -> bytes:
        """encrypt() çıktısını çözer."""


class PlainCipher(Cipher):
    """Güvensiz mod: veri olduğu gibi gönderilir."""

    name = "plain"

    def encrypt(self, plaintext: bytes) -> bytes:
        return plaintext

    def decrypt(self, data: bytes) -> bytes:
        return data
