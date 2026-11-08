import socket
import unittest

from common.protocol import Connection, ConnectionClosed, Message, MessageType, decode, encode


class ProtocolTest(unittest.TestCase):
    def test_encode_decode(self):
        original = Message(MessageType.TEXT, {"msg_id": "abc", "from": "Ayşe"}, b"\x00\x01merhaba")
        data = encode(original)
        header_len = int.from_bytes(data[:4], "big")
        decoded = decode(data[8:8 + header_len], data[8 + header_len:])
        self.assertEqual(decoded.type, MessageType.TEXT)
        self.assertEqual(decoded.header, {"msg_id": "abc", "from": "Ayşe"})
        self.assertEqual(decoded.payload, original.payload)
        self.assertEqual(decoded.wire_size, len(data))

    def test_connection_roundtrip(self):
        a, b = socket.socketpair()
        left, right = Connection(a), Connection(b)
        messages = [
            Message(MessageType.HELLO, {"name": "x"}),
            Message(MessageType.FILE_CHUNK, {"index": 3}, bytes(range(256)) * 50),
        ]
        for m in messages:
            left.send(m)
        for m in messages:
            received = right.recv()
            self.assertEqual((received.type, received.payload), (m.type, m.payload))
        self.assertEqual(left.bytes_sent, right.bytes_received)
        left.close()
        with self.assertRaises(ConnectionClosed):
            right.recv()
        right.close()


if __name__ == "__main__":
    unittest.main()
