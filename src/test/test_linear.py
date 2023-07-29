import os
from unittest import TestCase

from src.cipher import Cipher
from src.linear import LinearAnalyzer, _xor_sum


class TestLinearAnalyzer(TestCase):

    def test_break_last_round_key_success_rate(self):
        tries = 20
        successes = 0
        for i in range(tries):
            cipher = Cipher(os.urandom(Cipher.KEY_LENGTH))
            analyzer = LinearAnalyzer(cipher)
            expected = cipher._key[-1].to_bytes(Cipher.BLOCK_SIZE, byteorder="big")
            actual = analyzer.break_last_round_key()
            if expected == actual:
                successes += 1
        self.assertGreater(successes / tries, 0.5)

    def test__xor_sum(self):
        expected = 0
        actual = _xor_sum(0x7, 0x5)
        self.assertEqual(expected, actual)

        expected = 1
        actual = _xor_sum(0xf2, 0x93)
        self.assertEqual(expected, actual)
