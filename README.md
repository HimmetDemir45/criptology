# Güvenli Haberleşme Projesi

**Sunucu – İstemci – İstemci | Güvensiz ve Güvenli Mod | RSA – DH – ECC – Kyber Karşılaştırması | Wireshark Paket Analizi**

Bilgi Güvenliği ve Kriptoloji dersi (Dr. Hakan AYDIN) — KTÜ Of Teknoloji Fakültesi, Yazılım Mühendisliği, 2026–2027 Güz

## Grup Üyeleri

| Ad Soyad      | Öğrenci No | Ana Sorumluluk                                      |
|---------------|------------|-----------------------------------------------------|
| Himmet Demir  | 457261     | Sunucu, haberleşme protokolü, entegrasyon           |
| Yunus Özkan   | 445873     | Kütüphanesiz AES-128, istemci arayüzü (GUI)         |
| Gürkan Kaya   | 445892     | Anahtar dağıtım yöntemleri, ölçümler, Wireshark     |

---

## 1. Proje Özeti

- Bir **sunucu** ve iki **istemci** uygulaması vardır. Sistem en az **2 bilgisayarda** çalışır.
- İstemciler birbirine doğrudan bağlanmaz: her mesaj önce sunucuya gider, sunucu onu diğer istemciye iletir.
- İstemci iki şey gönderebilir: **klavyeden yazılan metin** ve **bilgisayardan seçilen PDF dosyası**.
- **Güvensiz mod:** Veri şifrelenmeden gider, Wireshark'ta içerik açıkça okunur.
- **Güvenli mod:** İstemci ile sunucu arasında önce bir **AES-128 anahtarı** paylaşılır; metin ve dosya parçaları bu anahtarla AES ile şifrelenir. Sunucu veriyi çözer, ekrana yazar (dosyaysa kaydeder) ve diğer istemciye **o istemcinin anahtarıyla yeniden şifreleyerek** iletir.
- AES anahtarını paylaşmak için 4 yöntem vardır; kullanıcı program başlarken birini seçer:

| Yöntem              | Anahtar nasıl paylaşılır?                                                                 |
|---------------------|-------------------------------------------------------------------------------------------|
| RSA-2048            | İstemci rastgele AES anahtarı üretir, sunucunun açık anahtarıyla şifreleyip gönderir.     |
| Diffie-Hellman 2048 | İki taraf açık değerlerini karşılıklı gönderir, ortak anahtarı kendileri hesaplar.        |
| ECC (ECDH)          | DH ile aynı fikir, eliptik eğri üzerinde.                                                 |
| Kyber (ML-KEM-768)  | Sunucu açık anahtar gönderir, istemci gizli değeri kapsüller, sunucu açar.                |

> RSA, DH, ECC ve Kyber **veri şifrelemek için değil**, AES anahtarını iki tarafa güvenli şekilde ulaştırmak için kullanılır. Verinin kendisi her zaman AES ile şifrelenir.

---

## 2. Görev Dağılımı

### Himmet Demir (457261) — Sunucu, Protokol, Entegrasyon
- [x] Proje iskeleti, klasör yapısı, ortak sınıf arayüzleri (OOP), `requirements.txt`
- [x] Haberleşme protokolü: mesaj çerçeveleme (uzunluk + başlık + veri), mesaj tipleri (`HELLO`, `KX_SERVER`, `KX_CLIENT`, `KX_DONE`, `WELCOME`, `TEXT`, `FILE_START`, `FILE_CHUNK`, `FILE_END`, `ACK`, `INFO`, `ERROR`, `BYE`)
- [x] Sunucu: iki istemciyi kabul etme, istemci başına ayrı AES anahtarı tutma, mesajı çözüp ekrana yazma / dosyayı kaydetme, diğer istemcinin anahtarıyla yeniden şifreleyip iletme
- [x] İstemci ağ katmanı (bağlanma, gönderme, alma) — GUI'den bağımsız bir sınıf (+ test için komut satırı istemcisi)
- [x] PDF dosyasını parçalara bölme ve karşı tarafta birleştirme
- [x] Güvensiz / güvenli mod geçişi
- [ ] Modüllerin birleştirilmesi (AES + anahtar dağıtım + GUI), iki bilgisayarda uçtan uca test
- [x] README'nin kurulum ve çalıştırma bölümü
- **Rapor:** Kapak, 1. Giriş, 2. Sistem Mimarisi, 3. Güvenli Mod Akışı, 9. Görev Dağılımı, raporun birleştirilmesi

### Yunus Özkan (445873) — Kütüphanesiz AES-128, İstemci Arayüzü
- [ ] **Kütüphanesiz AES-128:** S-box / ters S-box, `SubBytes`, `ShiftRows`, `MixColumns` (GF(2⁸) çarpımı), `AddRoundKey`, anahtar genişletme (11 tur anahtarı), 10 tur, şifre çözme (ters dönüşümler)
- [ ] Çalışma modu (CBC + rastgele IV) ve PKCS#7 padding
- [ ] FIPS-197 test vektörleri ile doğrulama (birim testleri)
- [ ] Aynı girdi için **manuel AES ile kütüphaneli AES çıktısının karşılaştırılması**; farkların (padding, çalışma modu, IV) açıklanması
- [ ] İstemci arayüzü (GUI): sunucu IP/port, mod seçimi (güvensiz/güvenli), anahtar dağıtım yöntemi seçimi, metin gönderme, PDF seçip gönderme, gelen mesajlar ve dosyalar listesi
- [ ] GUI ayrı bir bileşen olacak; ağ katmanını dışarıdan çağıracak (iş mantığı GUI içine yazılmayacak)
- **Rapor:** 5. Manuel AES

### Gürkan Kaya (445892) — Anahtar Dağıtım, Ölçümler, Wireshark
- [ ] Ortak bir `KeyExchange` arayüzü ve 4 uygulaması: **RSA-2048**, **DH-2048**, **ECDH**, **ML-KEM-768 (Kyber)**
- [ ] Her yöntemin sonunda 16 byte'lık AES-128 anahtarının iki tarafta da aynı çıktığının doğrulanması (DH/ECDH/Kyber için ortak sırdan HKDF/SHA-256 ile türetme)
- [ ] Ölçüm betiği — her yöntem için **10 ölçümün ortalaması**:
  1. anahtar üretme süresi (ms)
  2. anahtar değişimi süresi (ms)
  3. anahtar değişimi sırasında ağa giden paket boyutu (byte)
- [ ] Sonuç tablosu ve yorumu, kuantum dayanıklılığı paragrafı
- [ ] Wireshark yakalamaları: **en az iki bilgisayarda** (sunucu tarafı ve istemci tarafı), her mod için en az bir `.pcapng`
- [ ] Ekran görüntüleri: güvensiz modda metnin açıkça okunduğu, güvenli modda okunamadığı paketler
- **Rapor:** 4. Anahtar Dağıtım Yöntemleri, 6. Wireshark Analizi

### Ortak Görevler (herkes)
- [ ] Rapor 7. Karşılaşılan Sorunlar ve Çözümler — herkes kendi kısmında yaşadığı sorunları yazar (güvenlik duvarı, paket kaybı, kütüphane kurulumu vb.)
- [ ] Rapor 8. Sonuç ve Ekler (kaynakça, `.pcapng` listesi)
- [ ] Haftalık klasik şifreleme ödevleri (aşağıdaki tablo)
- [ ] Sunum hazırlığı ve soru-cevap: herkes kendi kısmını sunar ve **tüm projeyi anlatabilecek** durumda olur
- [ ] Herkes kendi işini kendi hesabından commit'ler (rapordaki commit özeti için önemli)

### Klasik Şifreleme Ödevleri

Slaytlara göre klasik yöntemler de kodlanıp repoya eklenecek. Öneri dağılım:

| Himmet Demir         | Yunus Özkan        | Gürkan Kaya            |
|----------------------|--------------------|------------------------|
| Caesar ✅            | Vigenère           | Affine                 |
| Substitution ✅      | Hill               | Rail Fence             |
| Playfair ✅          | Polybius           | Columnar Transposition |

---

## 3. Önerilen Klasör Yapısı

```
criptology/
├── server/            # Sunucu ve yönlendirme mantığı
├── client/
│   ├── network/       # İstemci ağ katmanı (GUI'den bağımsız)
│   ├── gui/           # Arayüz bileşenleri
│   └── cli.py         # Komut satırı istemcisi (test ve Wireshark çekimi için)
├── common/            # Protokol, mesaj tipleri, ayarlar
├── crypto/
│   ├── aes_manual/    # Kütüphanesiz AES-128
│   ├── aes_lib/       # Kütüphaneli AES (karşılaştırma için)
│   └── key_exchange/  # RSA, DH, ECDH, Kyber
├── classic/           # Klasik şifreleme yöntemleri
├── benchmarks/        # Ölçüm betikleri ve sonuç tabloları
├── tests/             # Birim testleri (AES test vektörleri vb.)
├── captures/          # Wireshark .pcapng dosyaları
├── docs/              # Rapor (PDF), diyagramlar, ekran görüntüleri
└── README.md
```

## 4. Güvenli Mod Akışı (Özet)

1. İstemci sunucuya bağlanır, mod ve anahtar dağıtım yöntemini bildirir (`HELLO`).
2. Seçilen yöntemle (RSA / DH / ECDH / Kyber) AES-128 anahtarı paylaşılır: sunucu ilk mesajı gönderir (`KX_SERVER`), istemci cevaplar (`KX_CLIENT`), sunucu süre ve byte ölçümlerini bildirir (`KX_DONE`), ardından bağlantı hazırdır (`WELCOME`).
3. İstemci metni veya PDF parçalarını AES ile şifreleyip gönderir (`TEXT` / `FILE_CHUNK` / `FILE_END`).
4. Sunucu gönderenin anahtarıyla çözer, ekrana yazar veya dosyayı kaydeder.
5. Sunucu veriyi alıcının anahtarıyla yeniden şifreleyip diğer istemciye iletir.
6. Alıcı çözer ve `ACK` döner; sunucu `ACK`'yi gönderene iletir.

## 5. Çalışma Düzeni

- `main` dalına doğrudan push yapılmaz. Herkes kendi dalında çalışır (`feature/sunucu`, `feature/aes-manual`, `feature/key-exchange` vb.) ve Pull Request açar; en az bir kişi inceleyip birleştirir.
- Commit mesajları kısa ve açıklayıcı olur (ör. `AES: MixColumns ve testleri eklendi`).
- Kod okunaklı, sınıflara ayrılmış ve yorumlanmış olur; her üye kendi yazdığı kodu açıklayabilmelidir.

## 6. Takvim

| Aşama                                                        | Teslim                                   | Tarih |
|--------------------------------------------------------------|------------------------------------------|-------|
| Grupların oluşturulması, platform ve dil seçimi, görev dağılımı | Grup bilgi formu (isimler, numaralar, GitHub linki) | _belirlenecek_ |
| Wireshark yakalamaları, rapor yazımı                         | Rapor, kod, `.pcapng` dosyaları          | _belirlenecek_ |
| Sunum ve soru-cevap                                          | —                                        | Final haftasından 2 hafta önce |

## 7. Teslim Edilecekler

1. **Teknik rapor** (PDF, 6–10 sayfa) — `docs/`
2. **Kodlar** — sunucu, istemci ve manuel algoritma dosyaları bu repoda
3. **Wireshark kayıtları** — her mod için en az bir `.pcapng` — `captures/`

## 8. Kurulum ve Çalıştırma

### Gereksinimler
- Python 3.10 veya üzeri
- Bağımlılıklar:

```bash
pip install -r requirements.txt
```

### Hangi bilgisayarda ne çalışır?

| Bilgisayar     | Program                    | Komut                                   |
|----------------|----------------------------|-----------------------------------------|
| Bilgisayar 1   | Sunucu                     | `python -m server`                      |
| Bilgisayar 2   | İstemci 1                  | `python -m client.cli --host <sunucu IP> --name Ali` |
| Bilgisayar 2/3 | İstemci 2                  | `python -m client.cli --host <sunucu IP> --name Veli` |

Komutlar reponun kök klasöründe çalıştırılır. Sunucu açılınca istemcilerin bağlanacağı IP adreslerini ekrana yazar. PyQt arayüzü hazır olunca komut satırı istemcisinin yerini alacak.

### Sunucu

```bash
python -m server --port 5000 --aes lib
```

- `--aes lib|manual`: güvenli modda kütüphaneli veya kütüphanesiz AES kullanılır (iki taraf da aynısını seçmeli).
- Gelen dosyalar `server_received/<istemci adı>/` altına kaydedilir.

### İstemci (komut satırı)

```bash
python -m client.cli --host 192.168.1.10 --name Ali --mode insecure
python -m client.cli --host 192.168.1.10 --name Ali --mode secure --method rsa
```

- `--mode insecure|secure`, `--method rsa|dh|ecdh|kyber` (güvenli mod için).
- Yazılan her satır metin olarak gider. `/dosya C:/Belgeler/rapor.pdf` dosya gönderir, `/cik` çıkar.
apor.pdf` dosya gönderir, `/cik` çıkar.
- Gelen dosyalar `received/` klasörüne kaydedilir.

### Güvenlik Duvarı (Windows)
Sunucu bilgisayarında 5000 numaralı TCP portuna gelen bağlantılara izin verilmelidir. İlk çalıştırmada Windows'un sorduğu pencerede **Özel ağ** seçeneğine izin verin ya da yönetici olarak açılan bir terminalde:

```bash
netsh advfirewall firewall add rule name="Kriptoloji Sunucu" dir=in action=allow protocol=TCP localport=5000
```

### Testler

```bash
python -m unittest -v
```

Sunucu ve iki istemciyi aynı bilgisayarda başlatıp güvensiz, güvenli ve karma modda metin ve dosya aktarımını, ACK akışını, dolu sunucuyu ve hatalı yöntem seçimini test eder. Gerçek anahtar dağıtım yöntemleri eklenene kadar güvenli mod testleri yalnızca test amaçlı bir yöntem (`test-plain`) kullanır.

### Wireshark
Filtre: `tcp.port == 5000`. Güvensiz modda metin ve PDF içeriği paketlerde açıkça görünür; güvenli modda veri kısmı AES ile şifreli olduğu için okunamaz.
