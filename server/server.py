"""Sunucu: iki istemciyi kabul eder ve aralarındaki mesajları yönlendirir.

İstemciler birbirine doğrudan bağlanmaz. Her mesaj önce sunucuya gelir; sunucu
gönderenin anahtarıyla çözer, ekrana yazar (dosyaysa kaydeder) ve diğer istemciye
o istemcinin anahtarıyla yeniden şifreleyerek iletir. Güvensiz moddaki istemci
için "anahtar" PlainCipher'dır, yani veri olduğu gibi iletilir.
"""

from __future__ import annotations

import json
import os
import socket
import threading
import time
from datetime import datetime
from typing import Callable

from common import config
from common.files import IncomingFile
from common.protocol import (
    Connection, ConnectionClosed, Message, MessageType, Mode, ProtocolError,
)
from crypto import create_cipher
from crypto.cipher import Cipher, PlainCipher
from crypto.key_exchange import get_method


def _log_to_console(text: str) -> None:
    print(f"[{datetime.now():%H:%M:%S}] {text}", flush=True)


class ClientSession:
    """Sunucuya bağlı bir istemcinin durumu."""

    def __init__(self, conn: Connection, address: tuple[str, int], client_id: int):
        self.conn = conn
        self.address = address
        self.client_id = client_id
        self.name = f"istemci-{client_id}"
        self.mode = Mode.INSECURE
        self.method: str | None = None
        self.cipher: Cipher = PlainCipher()
        self.incoming_files: dict[str, IncomingFile] = {}
        self.kx_stats: dict | None = None
        # El sıkışma bitene kadar bu istemciye mesaj iletilmez; aksi halde anahtar
        # henüz paylaşılmamışken veri şifresiz gidebilirdi.
        self.ready = False

    def __str__(self) -> str:
        return f"{self.name} ({self.address[0]}:{self.address[1]})"


class Server:
    def __init__(
        self,
        host: str = config.DEFAULT_HOST,
        port: int = config.DEFAULT_PORT,
        save_dir: str = config.SERVER_SAVE_DIR,
        aes_impl: str = "lib",
        log: Callable[[str], None] = _log_to_console,
    ):
        self.host = host
        self.port = port
        self.save_dir = save_dir
        self.aes_impl = aes_impl
        self.log = log
        self._sessions: list[ClientSession] = []
        self._lock = threading.Lock()
        self._next_id = 1
        self._listener: socket.socket | None = None
        self._running = threading.Event()

    # ------------------------------------------------------------------ yaşam döngüsü

    def start(self) -> None:
        """Dinlemeye başlar ve bağlantıları arka planda kabul eder."""
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((self.host, self.port))
        self._listener.listen()
        self.port = self._listener.getsockname()[1]  # port 0 verildiyse gerçek port
        self._running.set()
        threading.Thread(target=self._accept_loop, name="accept", daemon=True).start()
        self.log(f"Sunucu {self.host}:{self.port} adresinde dinliyor (AES: {self.aes_impl})")

    def serve_forever(self) -> None:
        self.start()
        try:
            while self._running.is_set():
                time.sleep(0.5)
        except KeyboardInterrupt:
            self.log("Kapatılıyor...")
        finally:
            self.stop()

    def stop(self) -> None:
        self._running.clear()
        if self._listener:
            self._listener.close()
        with self._lock:
            sessions = list(self._sessions)
        for session in sessions:
            session.conn.close()

    @property
    def sessions(self) -> list[ClientSession]:
        with self._lock:
            return list(self._sessions)

    # ------------------------------------------------------------------ bağlantı kabulü

    def _accept_loop(self) -> None:
        while self._running.is_set():
            try:
                sock, address = self._listener.accept()
            except OSError:
                break
            threading.Thread(
                target=self._handle_client, args=(sock, address), daemon=True
            ).start()

    def _handle_client(self, sock: socket.socket, address: tuple[str, int]) -> None:
        conn = Connection(sock)
        with self._lock:
            if len(self._sessions) >= config.MAX_CLIENTS:
                full = True
            else:
                full = False
                session = ClientSession(conn, address, self._next_id)
                self._next_id += 1
                self._sessions.append(session)
        if full:
            self.log(f"{address[0]} reddedildi: sunucu dolu")
            self._send_quietly(conn, Message(MessageType.ERROR, {"message": "Sunucu dolu (en fazla 2 istemci)"}))
            conn.close()
            return

        try:
            self._handshake(session)
            self._notify_peer(session, f"{session.name} bağlandı", "peer_joined")
            self._receive_loop(session)
        except ConnectionClosed:
            pass
        except (ProtocolError, ValueError, KeyError, OSError, socket.timeout) as exc:
            self.log(f"{session} hata: {exc}")
            self._send_quietly(conn, Message(MessageType.ERROR, {"message": str(exc)}))
        finally:
            self._remove(session)

    def _remove(self, session: ClientSession) -> None:
        with self._lock:
            if session not in self._sessions:
                return
            self._sessions.remove(session)
        for incoming in session.incoming_files.values():
            incoming.abort()
        session.conn.close()
        self.log(f"{session} ayrıldı")
        if session.ready:
            self._notify_peer(session, f"{session.name} ayrıldı", "peer_left")

    # ------------------------------------------------------------------ el sıkışma

    def _handshake(self, session: ClientSession) -> None:
        conn = session.conn
        conn.settimeout(config.HANDSHAKE_TIMEOUT)

        hello = conn.recv()
        if hello.type != MessageType.HELLO:
            raise ProtocolError(f"HELLO bekleniyordu, {hello.type.value} geldi")
        session.name = str(hello.get("name") or session.name)[:32]
        session.mode = Mode(hello.get("mode", Mode.INSECURE.value))

        if session.mode == Mode.SECURE:
            session.method = hello.get("method")
            self._key_exchange(session)

        conn.settimeout(None)
        peer = self._peer_of(session)
        conn.send(Message(MessageType.WELCOME, {
            "client_id": session.client_id,
            "mode": session.mode.value,
            "method": session.method,
            "aes": self.aes_impl if session.mode == Mode.SECURE else None,
            "peer": peer.name if peer else None,
        }))
        session.ready = True
        detail = f"güvenli mod, {session.method}" if session.mode == Mode.SECURE else "güvensiz mod"
        self.log(f"{session} bağlandı ({detail})")

    def _key_exchange(self, session: ClientSession) -> None:
        conn = session.conn
        kx = get_method(session.method)

        started = time.perf_counter()
        first = Message(MessageType.KX_SERVER, {"method": kx.name}, kx.server_start())
        sent = conn.send(first)

        reply = conn.recv()
        if reply.type != MessageType.KX_CLIENT:
            raise ProtocolError(f"KX_CLIENT bekleniyordu, {reply.type.value} geldi")
        key = kx.server_finish(reply.payload)
        elapsed_ms = (time.perf_counter() - started) * 1000

        session.cipher = create_cipher(key, self.aes_impl)
        session.kx_stats = {
            "method": kx.name,
            "exchange_ms": round(elapsed_ms, 3),
            "bytes_server_to_client": sent,
            "bytes_client_to_server": reply.wire_size,
            "bytes_total": sent + reply.wire_size,
        }
        conn.send(Message(MessageType.KX_DONE, session.kx_stats))
        self.log(
            f"{session}: {kx.name} ile AES anahtarı paylaşıldı "
            f"({elapsed_ms:.2f} ms, {sent + reply.wire_size} byte)"
        )

    # ------------------------------------------------------------------ mesaj işleme

    def _receive_loop(self, session: ClientSession) -> None:
        handlers = {
            MessageType.TEXT: self._on_text,
            MessageType.FILE_START: self._on_file_start,
            MessageType.FILE_CHUNK: self._on_file_chunk,
            MessageType.FILE_END: self._on_file_end,
            MessageType.ACK: self._on_ack,
        }
        while True:
            message = session.conn.recv()
            if message.type == MessageType.BYE:
                return
            handler = handlers.get(message.type)
            if handler is None:
                raise ProtocolError(f"Beklenmeyen mesaj: {message.type.value}")
            handler(session, message)

    def _on_text(self, session: ClientSession, message: Message) -> None:
        plaintext = session.cipher.decrypt(message.payload)
        self.log(f"{session.name} -> metin: {plaintext.decode(config.ENCODING, errors='replace')}")
        self._relay(session, message, plaintext, ref=message.get("msg_id"))

    def _on_file_start(self, session: ClientSession, message: Message) -> None:
        meta = json.loads(session.cipher.decrypt(message.payload))
        transfer_id = message.get("transfer_id")
        directory = os.path.join(self.save_dir, session.name)
        session.incoming_files[transfer_id] = IncomingFile(
            directory, meta["name"], int(meta["size"]), int(meta["chunks"])
        )
        self.log(f"{session.name} -> dosya geliyor: {meta['name']} ({meta['size']} byte)")
        self._relay(session, message, json.dumps(meta).encode(config.ENCODING), ref=transfer_id)

    def _on_file_chunk(self, session: ClientSession, message: Message) -> None:
        incoming = self._incoming(session, message)
        data = session.cipher.decrypt(message.payload)
        incoming.write(data)
        self._relay(session, message, data, report_missing_peer=False)

    def _on_file_end(self, session: ClientSession, message: Message) -> None:
        incoming = self._incoming(session, message)
        meta = json.loads(session.cipher.decrypt(message.payload))
        del session.incoming_files[message.get("transfer_id")]
        if incoming.finish(meta.get("sha256")):
            self.log(f"{session.name} -> dosya kaydedildi: {incoming.path}")
        else:
            self.log(f"{session.name} -> UYARI: {incoming.name} bütünlük kontrolünden geçmedi")
        self._relay(session, message, json.dumps(meta).encode(config.ENCODING), report_missing_peer=False)

    def _on_ack(self, session: ClientSession, message: Message) -> None:
        # ACK alıcıdan gelir; mesajın asıl sahibine (diğer istemciye) iletilir.
        peer = self._peer_of(session)
        if peer:
            self._send_quietly(peer.conn, Message(MessageType.ACK, {**message.header, "from": session.name}))

    def _incoming(self, session: ClientSession, message: Message) -> IncomingFile:
        try:
            return session.incoming_files[message.get("transfer_id")]
        except KeyError:
            raise ProtocolError("FILE_START olmadan dosya parçası geldi") from None

    # ------------------------------------------------------------------ yönlendirme

    def _peer_of(self, session: ClientSession) -> ClientSession | None:
        with self._lock:
            for other in self._sessions:
                if other is not session and other.ready:
                    return other
        return None

    def _relay(
        self,
        sender: ClientSession,
        message: Message,
        plaintext: bytes,
        ref: str | None = None,
        report_missing_peer: bool = True,
    ) -> None:
        """Çözülmüş veriyi alıcının anahtarıyla yeniden şifreleyip iletir."""
        peer = self._peer_of(sender)
        if peer is None:
            if report_missing_peer:
                self._send_quietly(sender.conn, Message(MessageType.ERROR, {
                    "ref": ref, "message": "Karşı istemci bağlı değil; mesaj iletilemedi",
                }))
            return
        header = {**message.header, "from": sender.name}
        self._send_quietly(peer.conn, Message(message.type, header, peer.cipher.encrypt(plaintext)))

    def _notify_peer(self, session: ClientSession, text: str, event: str) -> None:
        peer = self._peer_of(session)
        if peer:
            self._send_quietly(peer.conn, Message(MessageType.INFO, {
                "event": event, "name": session.name, "message": text,
            }))

    @staticmethod
    def _send_quietly(conn: Connection, message: Message) -> None:
        try:
            conn.send(message)
        except OSError:
            pass
