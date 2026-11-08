"""Haberleşme protokolü: mesaj tipleri ve çerçeveleme.

TCP bir bayt akışıdır; mesajların nerede bitip nerede başladığını ayırt etmek için
her mesaj aşağıdaki çerçeve içinde gönderilir:

    +----------------------+----------------------+------------------+---------+
    | başlık uzunluğu (4B) | veri uzunluğu (4B)   | başlık (JSON)    | veri    |
    +----------------------+----------------------+------------------+---------+

- Uzunluklar big-endian işaretsiz 32 bit tamsayıdır.
- Başlık UTF-8 JSON'dur ve her zaman "type" alanını içerir.
- Veri (payload) ham baytlardır. Güvenli modda bu kısım AES ile şifrelenmiş olur,
  güvensiz modda metin/dosya içeriği olduğu gibi gider (Wireshark'ta okunur).
"""

from __future__ import annotations

import json
import socket
import struct
import threading
import uuid
from dataclasses import dataclass, field
from enum import Enum

from common.config import ENCODING, MAX_FRAME_SIZE


class MessageType(str, Enum):
    HELLO = "HELLO"            # istemci -> sunucu: ad, mod, anahtar dağıtım yöntemi
    KX_SERVER = "KX_SERVER"    # sunucu -> istemci: anahtar değişiminin ilk mesajı
    KX_CLIENT = "KX_CLIENT"    # istemci -> sunucu: anahtar değişiminin cevabı
    KX_DONE = "KX_DONE"        # sunucu -> istemci: anahtar paylaşıldı (süre, byte)
    WELCOME = "WELCOME"        # sunucu -> istemci: bağlantı hazır
    TEXT = "TEXT"              # metin mesajı
    FILE_START = "FILE_START"  # dosya aktarımı başlıyor (ad, boyut, parça sayısı)
    FILE_CHUNK = "FILE_CHUNK"  # dosya parçası
    FILE_END = "FILE_END"      # dosya aktarımı bitti (SHA-256 özeti)
    ACK = "ACK"                # alıcı mesajı/dosyayı aldığını bildirir
    INFO = "INFO"              # bilgilendirme (karşı istemci bağlandı/ayrıldı vb.)
    ERROR = "ERROR"            # hata bildirimi
    BYE = "BYE"                # bağlantıyı kapatma


class Mode(str, Enum):
    INSECURE = "insecure"
    SECURE = "secure"


class ProtocolError(Exception):
    """Bozuk veya beklenmeyen çerçeve."""


class ConnectionClosed(Exception):
    """Karşı taraf bağlantıyı kapattı."""


@dataclass
class Message:
    type: MessageType
    header: dict = field(default_factory=dict)
    payload: bytes = b""
    wire_size: int = 0  # Alınan/gönderilen çerçevenin toplam boyutu (byte)

    def get(self, key: str, default=None):
        return self.header.get(key, default)


def new_id() -> str:
    """Mesaj ve dosya aktarımları için kısa benzersiz kimlik."""
    return uuid.uuid4().hex[:12]


_LENGTHS = struct.Struct(">II")


def encode(message: Message) -> bytes:
    header = dict(message.header)
    header["type"] = message.type.value
    header_bytes = json.dumps(header, ensure_ascii=False).encode(ENCODING)
    return _LENGTHS.pack(len(header_bytes), len(message.payload)) + header_bytes + message.payload


def decode(header_bytes: bytes, payload: bytes) -> Message:
    try:
        header = json.loads(header_bytes.decode(ENCODING))
        msg_type = MessageType(header.pop("type"))
    except (ValueError, KeyError) as exc:
        raise ProtocolError(f"Geçersiz mesaj başlığı: {exc}") from exc
    return Message(msg_type, header, payload, _LENGTHS.size + len(header_bytes) + len(payload))


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    buffer = bytearray()
    while len(buffer) < size:
        chunk = sock.recv(size - len(buffer))
        if not chunk:
            raise ConnectionClosed("Bağlantı karşı taraf tarafından kapatıldı")
        buffer.extend(chunk)
    return bytes(buffer)


class Connection:
    """Bir soketi saran, çerçeveli mesaj gönderip alan sınıf.

    Gönderme işlemi kilitlidir; böylece farklı thread'ler (ör. sunucunun yönlendirme
    thread'i ve istemcinin kendi thread'i) aynı sokete aynı anda yazarken çerçeveler
    birbirine karışmaz.
    """

    def __init__(self, sock: socket.socket):
        self.sock = sock
        self._send_lock = threading.Lock()
        self.bytes_sent = 0
        self.bytes_received = 0

    def send(self, message: Message) -> int:
        data = encode(message)
        with self._send_lock:
            self.sock.sendall(data)
            self.bytes_sent += len(data)
        message.wire_size = len(data)
        return len(data)

    def recv(self) -> Message:
        header_len, payload_len = _LENGTHS.unpack(_recv_exact(self.sock, _LENGTHS.size))
        if header_len + payload_len > MAX_FRAME_SIZE:
            raise ProtocolError(f"Çerçeve çok büyük: {header_len + payload_len} byte")
        header_bytes = _recv_exact(self.sock, header_len)
        payload = _recv_exact(self.sock, payload_len) if payload_len else b""
        message = decode(header_bytes, payload)
        self.bytes_received += message.wire_size
        return message

    def settimeout(self, timeout: float | None) -> None:
        self.sock.settimeout(timeout)

    def close(self) -> None:
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()
