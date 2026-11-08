"""Sunucuyu başlatır: python -m server [--port 5000] [--aes lib|manual]"""

import argparse
import socket

from common import config
from crypto import AES_IMPLEMENTATIONS
from crypto.key_exchange import available_methods
from server.server import Server


def local_addresses() -> list[str]:
    """Bu bilgisayarın IPv4 adresleri (istemcilere hangi IP'yi gireceklerini göstermek için)."""
    try:
        addresses = socket.gethostbyname_ex(socket.gethostname())[2]
    except OSError:
        addresses = []
    return [a for a in addresses if not a.startswith("127.")] or ["127.0.0.1"]


def main() -> None:
    parser = argparse.ArgumentParser(description="Güvenli Haberleşme Projesi - Sunucu")
    parser.add_argument("--host", default=config.DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=config.DEFAULT_PORT)
    parser.add_argument("--aes", choices=AES_IMPLEMENTATIONS, default="lib",
                        help="Güvenli modda kullanılacak AES gerçeklemesi")
    parser.add_argument("--save-dir", default=config.SERVER_SAVE_DIR,
                        help="Gelen dosyaların kaydedileceği klasör")
    args = parser.parse_args()

    print("İstemciler bu adreslerden birine bağlanabilir:", ", ".join(local_addresses()))
    print("Kullanılabilir anahtar dağıtım yöntemleri:", ", ".join(available_methods()) or "henüz yok")
    Server(args.host, args.port, args.save_dir, args.aes).serve_forever()


if __name__ == "__main__":
    main()
