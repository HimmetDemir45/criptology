"""Anahtar dağıtım yöntemlerinin kaydı.

Yeni bir yöntem eklemek için (Gürkan Kaya):
1. Bu klasöre ör. `rsa_kx.py` dosyası ekle.
2. KeyExchange'den türeyen sınıfı yaz ve `@register` ile işaretle.
3. Modül adını aşağıdaki _MODULES listesine ekle (rsa/dh/ecdh/kyber hazır).

Sunucu ve istemci yöntemi `get_method("rsa")` gibi adıyla oluşturur.
"""

from __future__ import annotations

import importlib

from crypto.key_exchange.base import KeyExchange

_REGISTRY: dict[str, type[KeyExchange]] = {}
_MODULES = ("rsa_kx", "dh_kx", "ecdh_kx", "kyber_kx")


def register(cls: type[KeyExchange]) -> type[KeyExchange]:
    if not cls.name:
        raise ValueError(f"{cls.__name__} için 'name' tanımlanmalı")
    _REGISTRY[cls.name] = cls
    return cls


def available_methods() -> list[str]:
    return sorted(_REGISTRY)


def get_method(name: str) -> KeyExchange:
    try:
        return _REGISTRY[name]()
    except KeyError:
        available = ", ".join(available_methods()) or "henüz yok"
        raise KeyError(f"Bilinmeyen anahtar dağıtım yöntemi: '{name}' (mevcut: {available})") from None


def _load_builtin_methods() -> None:
    for module in _MODULES:
        try:
            importlib.import_module(f"{__name__}.{module}")
        except ModuleNotFoundError as exc:
            # Sadece dosyanın kendisi yoksa atla; dosya var ama içinde eksik bir
            # kütüphane varsa hatayı gizleme.
            if exc.name != f"{__name__}.{module}":
                raise


_load_builtin_methods()

__all__ = ["KeyExchange", "register", "available_methods", "get_method"]
