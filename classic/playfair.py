"""Playfair şifresi — Himmet Demir.

5x5 anahtar tablosu kullanılır (İngilizce alfabe, I ve J aynı hücrede).
Metin ikili harf gruplarına bölünür ve her ikili için:
- Aynı satırdaysa: her harf sağındakiyle değişir (çözmede solundakiyle).
- Aynı sütundaysa: her harf altındakiyle değişir (çözmede üstündekiyle).
- Değilse: dikdörtgenin karşı köşeleri alınır (harfler kendi satırında kalır).
Bir ikilideki iki harf aynıysa araya X konur; tek harf kalırsa sona X eklenir.
Türkçe karakterler Latin karşılıklarına çevrilir (Ç->C, Ğ->G, İ/I->I, Ö->O, Ş->S, Ü->U).
"""

from classic.base import ClassicCipher

_TR_TO_LATIN = str.maketrans("ÇĞİIÖŞÜçğıiöşü", "CGIIOSUCGIIOSU")
_GRID_LETTERS = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # J yok
_FILLER = "X"


def _normalize(text: str) -> str:
    text = text.translate(_TR_TO_LATIN).upper().replace("J", "I")
    return "".join(ch for ch in text if ch in _GRID_LETTERS)


class Playfair(ClassicCipher):
    name = "playfair"

    def __init__(self, key: str):
        seen = []
        for ch in _normalize(key) + _GRID_LETTERS:
            if ch not in seen:
                seen.append(ch)
        self.grid = [seen[i:i + 5] for i in range(0, 25, 5)]
        self._pos = {ch: (r, c) for r, row in enumerate(self.grid) for c, ch in enumerate(row)}

    def table(self) -> str:
        return "\n".join(" ".join(row) for row in self.grid)

    @staticmethod
    def _pairs(text: str) -> list[tuple[str, str]]:
        letters = _normalize(text)
        pairs = []
        i = 0
        while i < len(letters):
            a = letters[i]
            b = letters[i + 1] if i + 1 < len(letters) else _FILLER
            if a == b:
                # Aynı harf ikilisi: araya dolgu harfi koy, ikinci harf bir sonraki ikiliye kalır
                filler = _FILLER if a != _FILLER else "Q"
                pairs.append((a, filler))
                i += 1
            else:
                pairs.append((a, b))
                i += 2
        return pairs

    def _transform(self, pairs: list[tuple[str, str]], step: int) -> str:
        result = []
        for a, b in pairs:
            ra, ca = self._pos[a]
            rb, cb = self._pos[b]
            if ra == rb:
                result += [self.grid[ra][(ca + step) % 5], self.grid[rb][(cb + step) % 5]]
            elif ca == cb:
                result += [self.grid[(ra + step) % 5][ca], self.grid[(rb + step) % 5][cb]]
            else:
                result += [self.grid[ra][cb], self.grid[rb][ca]]
        return "".join(result)

    def encrypt(self, text: str) -> str:
        return self._transform(self._pairs(text), 1)

    def decrypt(self, text: str) -> str:
        letters = _normalize(text)
        if len(letters) % 2:
            raise ValueError("Playfair şifreli metni çift sayıda harf içermeli")
        pairs = [(letters[i], letters[i + 1]) for i in range(0, len(letters), 2)]
        return self._transform(pairs, -1)
