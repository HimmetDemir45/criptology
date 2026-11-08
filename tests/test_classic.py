import unittest

from classic import Caesar, Playfair, Substitution
from classic.base import EN_UPPER, TR_LOWER


class CaesarTest(unittest.TestCase):
    def test_english_example(self):
        self.assertEqual(Caesar(3, "en").encrypt("HELLO, world"), "KHOOR, zruog")

    def test_turkish_letters(self):
        self.assertEqual(Caesar(1).encrypt("Çağrı"), "Dbhsi")
        self.assertEqual(Caesar(1).encrypt("İzmir"), "Janjs")

    def test_roundtrip(self):
        text = "Kriptoloji dersi, Of Teknoloji Fakültesi! 2026"
        for shift in (0, 5, 28, 100, -7):
            cipher = Caesar(shift)
            self.assertEqual(cipher.decrypt(cipher.encrypt(text)), text)

    def test_brute_force_finds_plaintext(self):
        ciphertext = Caesar(11).encrypt("GÜVENLİ HABERLEŞME")
        self.assertIn((11, "GÜVENLİ HABERLEŞME"), Caesar.brute_force(ciphertext))


class SubstitutionTest(unittest.TestCase):
    def test_roundtrip_turkish(self):
        cipher = Substitution(Substitution.random_key())
        text = "Şifreli Ğüzel İçerik, ıslak ılık!"
        encrypted = cipher.encrypt(text)
        self.assertNotEqual(encrypted, text)
        self.assertEqual(cipher.decrypt(encrypted), text)

    def test_known_key_english(self):
        key = "QWERTYUIOPASDFGHJKLZXCVBNM"
        self.assertEqual(Substitution(key, "en").encrypt("Attack at dawn"), "Qzzqea qz rqvf")

    def test_invalid_key(self):
        with self.assertRaises(ValueError):
            Substitution("ABC", "en")
        with self.assertRaises(ValueError):
            Substitution(EN_UPPER, "tr")
        Substitution(TR_LOWER, "tr")  # küçük harfli anahtar da kabul edilir


class PlayfairTest(unittest.TestCase):
    def test_wikipedia_example(self):
        cipher = Playfair("playfair example")
        self.assertEqual(cipher.encrypt("Hide the gold in the tree stump"), "BMODZBXDNABEKUDMUIXMMOUVIF")
        self.assertEqual(cipher.decrypt("BMODZBXDNABEKUDMUIXMMOUVIF"), "HIDETHEGOLDINTHETREXESTUMP")

    def test_table_has_25_unique_letters(self):
        letters = Playfair("KRİPTOLOJİ").table().split()
        self.assertEqual(len(letters), 25)
        self.assertEqual(len(set(letters)), 25)
        self.assertEqual(letters[:5], ["K", "R", "I", "P", "T"])

    def test_turkish_and_odd_length(self):
        cipher = Playfair("anahtar")
        encrypted = cipher.encrypt("Güvenli")  # -> GUVENLI, 7 harf, sona X eklenir
        self.assertEqual(len(encrypted), 8)
        self.assertEqual(cipher.decrypt(encrypted), "GUVENLIX")


if __name__ == "__main__":
    unittest.main()
