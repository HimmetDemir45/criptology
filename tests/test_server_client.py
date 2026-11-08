"""Sunucu + iki istemci uçtan uca testleri (aynı bilgisayarda, 127.0.0.1)."""

import os
import queue
import shutil
import tempfile
import unittest

from client.network import ChatClient, ClientListener
from common.protocol import Mode
from crypto.key_exchange import KeyExchange, register
from server.server import Server

TIMEOUT = 5


@register
class _TestOnlyKeyExchange(KeyExchange):
    """SADECE TEST İÇİN: anahtarı açık gönderir, gerçek yöntemlerin yerini tutar.
    Gerçek yöntemler (rsa, dh, ecdh, kyber) Gürkan'ın modüllerinden gelecek."""

    name = "test-plain"

    def server_start(self) -> bytes:
        self._key = os.urandom(16)
        return self._key

    def client_respond(self, server_message: bytes) -> tuple[bytes, bytes]:
        return b"ok", server_message

    def server_finish(self, client_message: bytes) -> bytes:
        return self._key


class RecordingListener(ClientListener):
    def __init__(self):
        self.events = queue.Queue()

    def on_text(self, sender, text, msg_id):
        self.events.put(("text", sender, text, msg_id))

    def on_file_received(self, sender, path, ok):
        self.events.put(("file", sender, path, ok))

    def on_ack(self, ref, sender):
        self.events.put(("ack", ref, sender))

    def on_info(self, message):
        self.events.put(("info", message))

    def on_error(self, message):
        self.events.put(("error", message))

    def next(self, kind):
        while True:
            event = self.events.get(timeout=TIMEOUT)
            if event[0] == kind:
                return event


class ServerClientTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.server = Server("127.0.0.1", 0, os.path.join(self.tmp, "server"), log=lambda _: None)
        self.server.start()
        self.clients = []

    def tearDown(self):
        for client in self.clients:
            client.close()
        self.server.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def connect(self, name, mode=Mode.INSECURE, method=None):
        listener = RecordingListener()
        client = ChatClient("127.0.0.1", self.server.port, name, mode, method, listener,
                            os.path.join(self.tmp, name))
        client.connect()
        self.clients.append(client)
        return client, listener

    def connect_pair(self, mode_a, mode_b):
        a, la = self.connect("ali", *mode_a)
        b, lb = self.connect("bora", *mode_b)
        la.next("info")  # "bora bağlandı"
        return a, la, b, lb

    def check_text_and_file(self, a, la, b, lb):
        msg_id = a.send_text("Merhaba Bora, şifreli mi?")
        _, sender, text, received_id = lb.next("text")
        self.assertEqual((sender, text, received_id), ("ali", "Merhaba Bora, şifreli mi?", msg_id))
        self.assertEqual(la.next("ack")[1], msg_id)

        pdf = os.path.join(self.tmp, "rapor.pdf")
        content = b"%PDF-1.4\n" + os.urandom(10_000)  # birden fazla parça
        with open(pdf, "wb") as f:
            f.write(content)
        transfer_id = b.send_file(pdf)
        _, sender, path, ok = la.next("file")
        self.assertTrue(ok)
        self.assertEqual(sender, "bora")
        with open(path, "rb") as f:
            self.assertEqual(f.read(), content)
        self.assertEqual(lb.next("ack")[1], transfer_id)
        with open(os.path.join(self.tmp, "server", "bora", "rapor.pdf"), "rb") as f:
            self.assertEqual(f.read(), content)

    def test_insecure_mode(self):
        self.check_text_and_file(*self.connect_pair((Mode.INSECURE,), (Mode.INSECURE,)))

    def test_secure_mode(self):
        a, la, b, lb = self.connect_pair((Mode.SECURE, "test-plain"), (Mode.SECURE, "test-plain"))
        self.assertEqual(a.cipher.name, "aes-lib")
        self.assertIsNotNone(a.kx_stats)
        self.assertGreater(a.kx_stats["bytes_total"], 0)
        # Her istemcinin sunucuyla ayrı anahtarı olmalı
        self.assertNotEqual(a.cipher.key, b.cipher.key)
        self.check_text_and_file(a, la, b, lb)

    def test_mixed_modes(self):
        self.check_text_and_file(*self.connect_pair((Mode.SECURE, "test-plain"), (Mode.INSECURE,)))

    def test_no_peer_reports_error(self):
        a, la = self.connect("yalniz")
        a.send_text("kimse yok mu?")
        self.assertIn("bağlı değil", la.next("error")[1])

    def test_third_client_rejected(self):
        self.connect_pair((Mode.INSECURE,), (Mode.INSECURE,))
        with self.assertRaisesRegex(ConnectionError, "dolu"):
            self.connect("ucuncu")

    def test_unknown_method_rejected(self):
        # İstemci yöntemi bağlanmadan önce kontrol eder
        with self.assertRaisesRegex(KeyError, "Bilinmeyen anahtar"):
            self.connect("x", Mode.SECURE, "yok-boyle-yontem")


if __name__ == "__main__":
    unittest.main()
