"""PyQt istemci arayüzü — Yunus Özkan.

Arayüz yalnızca client.network.ChatClient'ı kullanmalı, ağ/şifreleme mantığı
buraya yazılmamalıdır. Önerilen yapı:

- ClientListener'dan türeyen ve olayları Qt sinyallerine çeviren bir köprü sınıfı
  (olaylar arka plan thread'inden gelir; arayüz sadece ana thread'de güncellenir).
- connect() ve send_file() çağrıları QThread / threading ile arka planda.
- Bağlantı formu: sunucu IP/port, ad, mod (güvensiz/güvenli), yöntem seçimi
  (crypto.key_exchange.available_methods()), AES gerçeklemesi (lib/manual).
"""
