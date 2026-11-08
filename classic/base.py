"""Klasik şifreleme yöntemleri için ortak arayüz ve alfabe tanımları."""

from abc import ABC, abstractmethod

# Türk alfabesi (29 harf). Büyük ve küçük harfler aynı sırada:
# I <-> ı ve İ <-> i eşleşmesine dikkat (Python'un upper()/lower()'ı bunu yanlış yapar).
TR_UPPER = "ABCÇDEFGĞHIİJKLMNOÖPRSŞTUÜVYZ"
TR_LOWER = "abcçdefgğhıijklmnoöprsştuüvyz"

EN_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
EN_LOWER = "abcdefghijklmnopqrstuvwxyz"

ALPHABETS = {"tr": (TR_UPPER, TR_LOWER), "en": (EN_UPPER, EN_LOWER)}


def get_alphabet(name: str) -> tuple[str, str]:
    try:
        return ALPHABETS[name]
    except KeyError:
        raise ValueError(f"Bilinmeyen alfabe: {name} (tr veya en)") from None


class ClassicCipher(ABC):
    name = ""

    @abstractmethod
    def encrypt(self, text: str) -> str: ...

    @abstractmethod
    def decrypt(self, text: str) -> str: ...

    def encrypt_file(self, src: str, dst: str, encoding: str = "utf-8") -> None:
        """Metin dosyasını (.txt) şifreleyip yeni dosyaya yazar."""
        with open(src, encoding=encoding) as f:
            text = f.read()
        with open(dst, "w", encoding=encoding) as f:
            f.write(self.encrypt(text))

    def decrypt_file(self, src: str, dst: str, encoding: str = "utf-8") -> None:
        with open(src, encoding=encoding) as f:
            text = f.read()
        with open(dst, "w", encoding=encoding) as f:
            f.write(self.decrypt(text))
