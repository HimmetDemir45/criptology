"""Yerine koyma (Substitution) şifresi — Himmet Demir.

Anahtar, alfabenin bir permütasyonudur: alfabedeki i. harf anahtardaki i. harfle
değiştirilir. Türkçe için anahtar uzayı 29! (~8.8 x 10^30) olsa da şifre frekans
analizine karşı savunmasızdır; çünkü her harf hep aynı harfe dönüşür.
"""

import random

from classic.base import ClassicCipher, get_alphabet


class Substitution(ClassicCipher):
    name = "substitution"

    def __init__(self, key: str, alphabet: str = "tr"):
        self.upper, self.lower = get_alphabet(alphabet)
        key_upper = "".join(self.upper[self.lower.index(c)] if c in self.lower else c for c in key)
        if sorted(key_upper) != sorted(self.upper):
            raise ValueError(
                f"Anahtar alfabedeki {len(self.upper)} harfin her birini tam bir kez içermeli"
            )
        self.key = key_upper
        key_lower = "".join(self.lower[self.upper.index(c)] for c in key_upper)
        self._enc = {**dict(zip(self.upper, key_upper)), **dict(zip(self.lower, key_lower))}
        self._dec = {v: k for k, v in self._enc.items()}

    @classmethod
    def random_key(cls, alphabet: str = "tr") -> str:
        letters = list(get_alphabet(alphabet)[0])
        random.SystemRandom().shuffle(letters)
        return "".join(letters)

    def encrypt(self, text: str) -> str:
        return "".join(self._enc.get(ch, ch) for ch in text)

    def decrypt(self, text: str) -> str:
        return "".join(self._dec.get(ch, ch) for ch in text)
