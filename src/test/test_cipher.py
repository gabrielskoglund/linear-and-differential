import os
from random import randint
from unittest import TestCase

from src.cipher import Cipher


class TestCipher(TestCase):
    def test_cipher_key_requirement(self):
        try:
            _ = Cipher(b"")
        except ValueError:
            return
        self.fail()

    def test_encrypt(self):
        cipher = Cipher(b"\0" * Cipher.KEY_LENGTH)
        expected = b"\x41\x05\x40\xb8"
        actual = cipher.encrypt(b"\xab\xcd")
        self.assertEqual(expected, actual)

    def test_decrypt(self):
        cipher = Cipher(b"\0" * Cipher.KEY_LENGTH)
        expected = b"\xab\xcd"
        actual = cipher.decrypt(b"\x41\x05\x40\xb8")
        self.assertEqual(expected, actual)

    def test_encrypt_decrypt(self):
        for _ in range(100):
            key = os.urandom(Cipher.KEY_LENGTH)
            cipher = Cipher(key)
            plaintext = os.urandom(randint(0, 255))
            ciphertext = cipher.encrypt(plaintext)
            self.assertNotEqual(plaintext, ciphertext)
            self.assertEqual(plaintext, cipher.decrypt(ciphertext))

    def test__pad(self):
        cipher = Cipher(b"\0" * Cipher.KEY_LENGTH)
        expected = b"a\1"
        actual = cipher._pad(b"a")
        self.assertEqual(expected, actual)

    def test__substitute(self):
        cipher = Cipher(b"\0" * Cipher.KEY_LENGTH)
        expected = 0x4cf7
        actual = cipher._substitute(0x1b5f, cipher._S_BOX)
        self.assertEqual(expected, actual)

        expected = 0x1b5f
        actual = cipher._substitute(0x4cf7, cipher._S_BOX_INV)
        self.assertEqual(expected, actual)

    def test__permute(self):
        cipher = Cipher(b"\0" * Cipher.KEY_LENGTH)
        data = 0xaaaa  # Bits: 1010 1010 1010 1010
        expected = 0xf0f0  # Bits: 1111 0000 1111 0000
        actual = cipher._permute(data)
        self.assertEqual(expected, actual)
