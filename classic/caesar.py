"""Caesar (Sezar) şifresi — Himmet Demir.

Her harf alfabede `shift` kadar kaydırılır:
    şifreleme: c = (p + k) mod n
    çözme:     p = (c - k) mod n
n alfabedeki harf sayısıdır (Türkçe 29, İngilizce 26). Harf olmayan karakterler
ve büyük/küçük harf durumu korunur.
"""

from classic.base import ClassicCipher, get_alphabet


class Caesar(ClassicCipher):
    name = "caesar"

    def __init__(self, shift: int = 3, alphabet: str = "tr"):
        self.upper, self.lower = get_alphabet(alphabet)
        self.shift = shift % len(self.upper)

    def _shift_text(self, text: str, shift: int) -> str:
        n = len(self.upper)
        result = []
        for ch in text:
            if ch in self.upper:
                result.append(self.upper[(self.upper.index(ch) + shift) % n])
            elif ch in self.lower:
                result.append(self.lower[(self.lower.index(ch) + shift) % n])
            else:
                result.append(ch)
        return "".join(result)

    def encrypt(self, text: str) -> str:
        return self._shift_text(text, self.shift)

    def decrypt(self, text: str) -> str:
        return self._shift_text(text, -self.shift)

    @staticmethod
    def brute_force(ciphertext: str, alphabet: str = "tr") -> list[tuple[int, str]]:
        """Kaba kuvvet saldırısı: olası tüm kaydırmaları dener (anahtar uzayı çok küçük)."""
        size = len(get_alphabet(alphabet)[0])
        return [(k, Caesar(k, alphabet).decrypt(ciphertext)) for k in range(size)]
