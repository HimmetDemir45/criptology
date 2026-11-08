"""Şifreleme katmanı: AES gerçeklemeleri ve anahtar dağıtım yöntemleri."""

from crypto.cipher import Cipher, PlainCipher

AES_IMPLEMENTATIONS = ("lib", "manual")


def create_cipher(key: bytes, implementation: str = "lib") -> Cipher:
    """Paylaşılan AES anahtarıyla seçilen gerçeklemeden bir şifreleyici üretir."""
    if implementation == "lib":
        from crypto.aes_lib import LibraryAES
        return LibraryAES(key)
    if implementation == "manual":
        from crypto.aes_manual import ManualAES
        return ManualAES(key)
    raise ValueError(f"Bilinmeyen AES gerçeklemesi: {implementation}")
