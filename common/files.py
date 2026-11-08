"""Dosyaları parçalara bölme ve karşı tarafta birleştirme."""

from __future__ import annotations

import hashlib
import math
import os
from typing import Iterator

from common.config import CHUNK_SIZE


def chunk_count(size: int, chunk_size: int = CHUNK_SIZE) -> int:
    return max(1, math.ceil(size / chunk_size))


def iter_chunks(path: str, chunk_size: int = CHUNK_SIZE) -> Iterator[bytes]:
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            yield chunk


def sha256_of(path: str) -> str:
    digest = hashlib.sha256()
    for chunk in iter_chunks(path, 64 * 1024):
        digest.update(chunk)
    return digest.hexdigest()


def safe_filename(name: str) -> str:
    """Karşı taraftan gelen dosya adındaki klasör kısımlarını atar (../ saldırısına karşı)."""
    name = os.path.basename(name.replace("\\", "/")).strip()
    return name or "dosya"


def unique_path(directory: str, name: str) -> str:
    """Aynı adda dosya varsa üzerine yazmamak için ada (1), (2)... ekler."""
    base, ext = os.path.splitext(name)
    candidate = os.path.join(directory, name)
    counter = 1
    while os.path.exists(candidate):
        candidate = os.path.join(directory, f"{base} ({counter}){ext}")
        counter += 1
    return candidate


class IncomingFile:
    """Parça parça gelen bir dosyayı diske yazar ve sonunda bütünlüğünü kontrol eder."""

    def __init__(self, directory: str, name: str, size: int, chunks: int):
        os.makedirs(directory, exist_ok=True)
        self.name = safe_filename(name)
        self.size = size
        self.chunks = chunks
        self.received_chunks = 0
        self.path = unique_path(directory, self.name)
        self._file = open(self.path, "wb")
        self._digest = hashlib.sha256()

    def write(self, data: bytes) -> None:
        self._file.write(data)
        self._digest.update(data)
        self.received_chunks += 1

    def finish(self, expected_sha256: str | None) -> bool:
        """Dosyayı kapatır; özet eşleşiyorsa True döner."""
        self._file.close()
        return expected_sha256 is None or self._digest.hexdigest() == expected_sha256

    def abort(self) -> None:
        self._file.close()
        try:
            os.remove(self.path)
        except OSError:
            pass
