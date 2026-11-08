"""Anahtar dağıtım yöntemleri için ortak arayüz.

Her bağlantı için sunucuda ve istemcide bu sınıftan ayrı birer nesne oluşturulur.
Protokol akışı:

    Sunucu                                   İstemci
    msg = server_start()      --KX_SERVER-->
                                             reply, key = client_respond(msg)
    key = server_finish(reply) <--KX_CLIENT--

Sonunda iki tarafta da aynı 16 byte'lık AES-128 anahtarı elde edilmelidir.

Dört yöntem bu kalıba oturur:
- RSA-2048: sunucu açık anahtarını gönderir; istemci rastgele AES anahtarını
  bu açık anahtarla şifreleyip geri yollar.
- DH-2048 / ECDH: sunucu açık değerini gönderir; istemci kendi açık değerini
  yollar; iki taraf ortak sırrı hesaplayıp ondan AES anahtarını türetir.
- Kyber (ML-KEM-768): sunucu açık anahtarını gönderir; istemci kapsüller
  (encapsulate) ve şifreli metni yollar; sunucu açar (decapsulate).
"""

from abc import ABC, abstractmethod


class KeyExchange(ABC):
    name = ""          # Komut satırında/arayüzde seçilecek kısa ad, ör. "rsa"
    description = ""   # Arayüzde gösterilecek ad, ör. "RSA-2048"

    @abstractmethod
    def server_start(self) -> bytes:
        """Sunucu: anahtarları üretir ve istemciye gidecek ilk mesajı döner."""

    @abstractmethod
    def client_respond(self, server_message: bytes) -> tuple[bytes, bytes]:
        """İstemci: (sunucuya gidecek cevap, 16 byte AES anahtarı) döner."""

    @abstractmethod
    def server_finish(self, client_message: bytes) -> bytes:
        """Sunucu: istemcinin cevabından 16 byte AES anahtarını elde eder."""
