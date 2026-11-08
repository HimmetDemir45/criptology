"""Komut satırı istemcisi (arayüz hazır olana kadar test ve Wireshark çekimi için).

Örnek:
    python -m client.cli --host 192.168.1.10 --name Ali
    python -m client.cli --host 192.168.1.10 --name Ali --mode secure --method rsa

Komutlar:
    <metin>          metin gönderir
    /dosya <yol>     dosya (PDF) gönderir
    /cik             çıkış
"""

import argparse
import os

from client.network import ChatClient, ClientListener
from common import config
from common.protocol import Mode
from crypto import AES_IMPLEMENTATIONS


class ConsoleListener(ClientListener):
    def on_text(self, sender, text, msg_id):
        print(f"\n[{sender}] {text}")

    def on_file_started(self, sender, transfer_id, name, size):
        print(f"\n[{sender}] dosya gönderiyor: {name} ({size} byte)")

    def on_file_received(self, sender, path, ok):
        status = "kaydedildi" if ok else "BOZUK (özet eşleşmedi)"
        print(f"\n[{sender}] dosya {status}: {os.path.abspath(path)}")

    def on_ack(self, ref, sender):
        print(f"\n[{sender}] aldı (ACK {ref})")

    def on_info(self, message):
        print(f"\n[bilgi] {message}")

    def on_error(self, message):
        print(f"\n[hata] {message}")

    def on_disconnected(self):
        print("\n[bilgi] Sunucu bağlantısı kapandı")


def main() -> None:
    parser = argparse.ArgumentParser(description="Güvenli Haberleşme Projesi - Komut satırı istemcisi")
    parser.add_argument("--host", required=True, help="Sunucunun IP adresi")
    parser.add_argument("--port", type=int, default=config.DEFAULT_PORT)
    parser.add_argument("--name", required=True)
    parser.add_argument("--mode", choices=[m.value for m in Mode], default=Mode.INSECURE.value)
    parser.add_argument("--method", help="Güvenli mod için anahtar dağıtım yöntemi (rsa, dh, ecdh, kyber)")
    parser.add_argument("--aes", choices=AES_IMPLEMENTATIONS, default="lib")
    parser.add_argument("--download-dir", default=config.CLIENT_DOWNLOAD_DIR)
    args = parser.parse_args()

    client = ChatClient(args.host, args.port, args.name, Mode(args.mode), args.method,
                        ConsoleListener(), args.download_dir, args.aes)
    client.connect()
    print(f"Bağlandı (id={client.client_id}, mod={client.mode.value}). Karşı istemci: {client.peer or 'henüz yok'}")
    if client.kx_stats:
        print(f"Anahtar değişimi: {client.kx_stats}")

    try:
        while client.connected:
            line = input("> ").strip()
            if not line:
                continue
            if line == "/cik":
                break
            if line.startswith("/dosya "):
                path = line[len("/dosya "):].strip().strip('"')
                if not os.path.isfile(path):
                    print("Dosya bulunamadı")
                    continue
                client.send_file(path)
                print("Dosya gönderildi")
            else:
                client.send_text(line)
    except (EOFError, KeyboardInterrupt):
        pass
    finally:
        client.close()


if __name__ == "__main__":
    main()
