"""Sunucu ve istemcilerin ortak kullandığı ayarlar."""

DEFAULT_HOST = "0.0.0.0"   # Sunucu tüm ağ arayüzlerini dinler
DEFAULT_PORT = 5000

AES_KEY_SIZE = 16          # AES-128 -> 16 byte anahtar
AES_BLOCK_SIZE = 16

CHUNK_SIZE = 4096          # PDF dosyaları bu boyutta (byte) parçalara bölünür
MAX_FRAME_SIZE = 16 * 1024 * 1024  # Tek çerçeve için üst sınır (bozuk veriye karşı koruma)

HANDSHAKE_TIMEOUT = 30     # Saniye; anahtar değişimi bu sürede bitmezse bağlantı kesilir
MAX_CLIENTS = 2

SERVER_SAVE_DIR = "server_received"
CLIENT_DOWNLOAD_DIR = "received"

ENCODING = "utf-8"
