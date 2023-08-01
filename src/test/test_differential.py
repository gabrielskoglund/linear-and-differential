import os
from unittest import TestCase

from src.cipher import Cipher
from src.differential import DifferentialAnalyzer, KeyBreakingException


class TestDifferentialAnalyzer(TestCase):
    def test_break_last_round_key_success_rate(self):
        tries = 20
        successes = 0
        for _ in range(tries):
            key = os.urandom(Cipher.KEY_LENGTH)
            cipher = Cipher(key)
            analyzer = DifferentialAnalyzer(cipher)
            try:
                analyzer.break_key()
                successes += 1
            except KeyBreakingException:
                continue
        self.assertGreater(successes / tries, 0.5)

    def test__reverse_cipher(self):
        cipher = Cipher(b"0123456789")
        analyzer = DifferentialAnalyzer(cipher)
        ciphertext = int.from_bytes(b"ab", byteorder="big")
        expected = [52678, 2309, 4496, 20060]
        for i in range(1, 5):
            actual = analyzer._reverse_cipher(ciphertext, cipher._key[-i:])
            self.assertEqual(expected[i - 1], actual)
