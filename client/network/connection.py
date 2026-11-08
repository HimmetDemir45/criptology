"""İstemci ağ katmanı.

Arayüzden (GUI) tamamen bağımsızdır. Arayüz bu sınıfı dışarıdan çağırır
(connect, send_text, send_file, close) ve gelen olayları ClientListener
üzerinden alır. PyQt arayüzünde ClientListener'dan türeyen bir sınıf olayları
Qt sinyallerine çevirmelidir; çünkü olaylar arka plandaki alma thread'inden gelir.
"""

from __future__ import annotations

import json
import os
import socket
import threading
import time

from common import config
from common.files import IncomingFile, chunk_count, iter_chunks, sha256_of
from common.protocol import (
    Connection, ConnectionClosed, Message, MessageType, Mode, ProtocolError, new_id,
)
from crypto import create_cipher
from crypto.cipher import Cipher, PlainCipher
from crypto.key_exchange import get_method


class ClientListener:
    """Ağ katmanının olaylarını alan sınıf. İstenen metotlar ezilir (override)."""

    def on_text(self, sender: str, text: str, msg_id: str) -> None: ...
    def on_file_started(self, sender: str, transfer_id: str, name: str, size: int) -> None: ...
    def on_file_progress(self, transfer_id: str, done: int, total: int) -> None: ...
    def on_file_received(self, sender: str, path: str, ok: bool) -> None: ...
    def on_ack(self, ref: str, sender: str) -> None: ...
    def on_info(self, message: str) -> None: ...
    def on_error(self, message: str) -> None: ...
    def on_disconnected(self) -> None: ...


class ChatClient:
    def __init__(
        self,
        host: str,
        port: int = config.DEFAULT_PORT,
        name: str = "istemci",
        mode: Mode = Mode.INSECURE,
        method: str | None = None,
        listener: ClientListener | None = None,
        download_dir: str = config.CLIENT_DOWNLOAD_DIR,
        aes_impl: str = "lib",
    ):
        if mode == Mode.SECURE and not method:
            raise ValueError("Güvenli mod için anahtar dağıtım yöntemi seçilmeli")
        self.host = host
        self.port = port
        self.name = name
        self.mode = Mode(mode)
        self.method = method if self.mode == Mode.SECURE else None
        self.listener = listener or ClientListener()
        self.download_dir = download_dir
        self.aes_impl = aes_impl

        self.cipher: Cipher = PlainCipher()
        self.client_id: int | None = None
        self.peer: str | None = None
        self.kx_stats: dict | None = None   # Anahtar değişimi ölçümleri (rapor için)
        self._conn: Connection | None = None
        self._incoming: dict[str, IncomingFile] = {}
        self._incoming_sender: dict[str, str] = {}
        self._closing = False

    @property
    def connected(self) -> bool:
        return self._conn is not None and not self._closing

    # ------------------------------------------------------------------ bağlantı

    def connect(self) -> None:
        """Sunucuya bağlanır, gerekirse anahtar paylaşır ve alma thread'ini başlatır.

        Bloklayan bir çağrıdır; arayüz donmasın diye ayrı bir thread'de çağrılabilir.
        Başarısız olursa ConnectionError fırlatır.
        """
        kx = get_method(self.method) if self.mode == Mode.SECURE else None  # yöntem yoksa hemen hata
        sock = socket.create_connection((self.host, self.port), timeout=config.HANDSHAKE_TIMEOUT)
        conn = Connection(sock)
        try:
            conn.send(Message(MessageType.HELLO, {
                "name": self.name, "mode": self.mode.value, "method": self.method,
            }))
            if kx is not None:
                self._key_exchange(conn, kx)
            welcome = self._expect(conn, MessageType.WELCOME)
        except Exception:
            conn.close()
            raise
        conn.settimeout(None)
        self.client_id = welcome.get("client_id")
        self.peer = welcome.get("peer")
        self._conn = conn
        self._closing = False
        threading.Thread(target=self._receive_loop, name="receive", daemon=True).start()

    def _key_exchange(self, conn: Connection, kx) -> None:
        first = self._expect(conn, MessageType.KX_SERVER)
        started = time.perf_counter()
        reply, key = kx.client_respond(first.payload)
        conn.send(Message(MessageType.KX_CLIENT, {"method": kx.name}, reply))
        client_ms = (time.perf_counter() - started) * 1000
        done = self._expect(conn, MessageType.KX_DONE)
        self.cipher = create_cipher(key, self.aes_impl)
        self.kx_stats = {**done.header, "client_ms": round(client_ms, 3)}

    @staticmethod
    def _expect(conn: Connection, expected: MessageType) -> Message:
        message = conn.recv()
        if message.type == MessageType.ERROR:
            raise ConnectionError(message.get("message", "Sunucu bağlantıyı reddetti"))
        if message.type != expected:
            raise ProtocolError(f"{expected.value} bekleniyordu, {message.type.value} geldi")
        return message

    def close(self) -> None:
        if self._conn is None or self._closing:
            return
        self._closing = True
        try:
            self._conn.send(Message(MessageType.BYE))
        except OSError:
            pass
        self._conn.close()

    # ------------------------------------------------------------------ gönderme

    def send_text(self, text: str) -> str:
        msg_id = new_id()
        payload = self.cipher.encrypt(text.encode(config.ENCODING))
        self._send(Message(MessageType.TEXT, {"msg_id": msg_id}, payload))
        return msg_id

    def send_file(self, path: str) -> str:
        """Dosyayı parçalara bölüp gönderir. Büyük dosyalarda arayüz bunu ayrı
        thread'de çağırmalıdır; ilerleme on_file_progress ile bildirilir."""
        size = os.path.getsize(path)
        total = chunk_count(size)
        transfer_id = new_id()
        meta = {"name": os.path.basename(path), "size": size, "chunks": total}
        self._send(Message(MessageType.FILE_START, {"transfer_id": transfer_id},
                           self.cipher.encrypt(json.dumps(meta).encode(config.ENCODING))))
        for index, chunk in enumerate(iter_chunks(path)):
            self._send(Message(MessageType.FILE_CHUNK, {"transfer_id": transfer_id, "index": index},
                               self.cipher.encrypt(chunk)))
            self.listener.on_file_progress(transfer_id, index + 1, total)
        end = {"sha256": sha256_of(path)}
        self._send(Message(MessageType.FILE_END, {"transfer_id": transfer_id},
                           self.cipher.encrypt(json.dumps(end).encode(config.ENCODING))))
        return transfer_id

    def _send(self, message: Message) -> None:
        if not self.connected:
            raise ConnectionError("Sunucuya bağlı değil")
        self._conn.send(message)

    # ------------------------------------------------------------------ alma

    def _receive_loop(self) -> None:
        try:
            while True:
                self._dispatch(self._conn.recv())
        except (ConnectionClosed, OSError):
            pass
        except (ProtocolError, ValueError, KeyError) as exc:
            self.listener.on_error(f"Bağlantı hatası: {exc}")
        finally:
            for incoming in self._incoming.values():
                incoming.abort()
            self._incoming.clear()
            self._closing = True
            self._conn.close()
            self.listener.on_disconnected()

    def _dispatch(self, message: Message) -> None:
        sender = message.get("from", "sunucu")
        if message.type == MessageType.TEXT:
            text = self.cipher.decrypt(message.payload).decode(config.ENCODING, errors="replace")
            msg_id = message.get("msg_id")
            self._ack(msg_id)
            self.listener.on_text(sender, text, msg_id)
        elif message.type == MessageType.FILE_START:
            meta = json.loads(self.cipher.decrypt(message.payload))
            transfer_id = message.get("transfer_id")
            self._incoming[transfer_id] = IncomingFile(
                self.download_dir, meta["name"], int(meta["size"]), int(meta["chunks"])
            )
            self._incoming_sender[transfer_id] = sender
            self.listener.on_file_started(sender, transfer_id, meta["name"], int(meta["size"]))
        elif message.type == MessageType.FILE_CHUNK:
            transfer_id = message.get("transfer_id")
            incoming = self._incoming[transfer_id]
            incoming.write(self.cipher.decrypt(message.payload))
            self.listener.on_file_progress(transfer_id, incoming.received_chunks, incoming.chunks)
        elif message.type == MessageType.FILE_END:
            transfer_id = message.get("transfer_id")
            incoming = self._incoming.pop(transfer_id)
            meta = json.loads(self.cipher.decrypt(message.payload))
            ok = incoming.finish(meta.get("sha256"))
            self._ack(transfer_id)
            self.listener.on_file_received(self._incoming_sender.pop(transfer_id, sender), incoming.path, ok)
        elif message.type == MessageType.ACK:
            self.listener.on_ack(message.get("ref"), sender)
        elif message.type == MessageType.INFO:
            if message.get("event") == "peer_joined":
                self.peer = message.get("name")
            elif message.get("event") == "peer_left":
                self.peer = None
            self.listener.on_info(message.get("message", ""))
        elif message.type == MessageType.ERROR:
            self.listener.on_error(message.get("message", "Bilinmeyen hata"))
        elif message.type == MessageType.BYE:
            raise ConnectionClosed()

    def _ack(self, ref: str | None) -> None:
        if ref:
            try:
                self._send(Message(MessageType.ACK, {"ref": ref}))
            except (ConnectionError, OSError):
                pass
