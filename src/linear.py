import os
from abc import ABC, abstractmethod
from typing import Dict, List, Tuple, Generator

from src.cipher import Cipher


def _xor_sum(data: int, mask: int) -> int:
    # Get the XOR-sum (sum mod 2) of the bits indicated by the mask.
    return (data & mask).bit_count() % 2


class _LinearApproximation(ABC):
    """
    A linear approximation of the cipher.
    """

    @abstractmethod
    def subkeys(self) -> Generator[int, None, None]:
        """
        The subkeys to be checked for this linear approximation.
        """
        pass

    @abstractmethod
    def linear_equivalence_holds(self, plaintext: int, ciphertext: int) -> bool:
        """
        Check if the linear equivalence expected by this approximation holds.
        """
        pass

    @abstractmethod
    def required_samples(self) -> int:
        """
        The number of samples required to have a good probability to successfully extract the subkey bits using
        this linear approximation.
        """
        pass


class _FifthRoundKeyBlock2And4(_LinearApproximation):
    """
    This is the linear approximation presented by Heys.

    Trail: Round 1: b -> [S12]
           Round 2: 4 -> [S22]
           Round 3: 4 -> [S32] and 4 -> S[34]
           Round 4: 5 -> [S42] and 5 -> S[44]
    Expected bias: 1/32
    Input bit pattern:  0x0b00
    Output bit pattern: 0x0505
    """

    def subkeys(self) -> Generator[int, None, None]:
        for subkey_bits in range(2 ** 8):
            yield (subkey_bits & 0xf0) << 4 | (subkey_bits & 0xf)

    def linear_equivalence_holds(self, plaintext: int, ciphertext: int) -> bool:
        return _xor_sum(plaintext, 0x0b00) == _xor_sum(ciphertext, 0x0505)

    def required_samples(self) -> int:
        return 10_000


class _FifthRoundKeyBlock1And3(_LinearApproximation):
    """
    Trail: Round 1: e -> [S11] and e -> [S13]
           Round 2: a -> [S22] and a -> [S24]
           Round 3: 5 -> [S32]
           Round 4: 4 -> [S41] and 4 -> S[43]
    Expected bias: 1/64
    Input bit pattern:  0xe0e0
    Output bit pattern: 0x4040
    """

    def subkeys(self) -> Generator[int, None, None]:
        for subkey_bits in range(2 ** 8):
            yield (subkey_bits & 0xf0) << 8 | (subkey_bits & 0xf) << 4

    def linear_equivalence_holds(self, plaintext: int, ciphertext: int) -> bool:
        return _xor_sum(plaintext, 0xe0e0) == _xor_sum(ciphertext, 0x4040)

    def required_samples(self) -> int:
        # Experimentally determined to give > 50% probability of successfully finding the correct subkey bits
        return 40_000


class LinearAnalyzer:
    """
    The LinearAnalyzer class provides functionality for breaking parts of a cipher key using
    linear cryptanalysis.
    """

    APPROXIMATIONS: List[_LinearApproximation] = [
        _FifthRoundKeyBlock2And4(),
        _FifthRoundKeyBlock1And3(),
    ]

    def __init__(self, cipher: Cipher):
        """
        Create a new LinearAnalyzer instance.
        :param cipher: The cipher to attack.
        """
        self.cipher = cipher
        self.samples: Dict[int, int] = {}

    def break_last_round_key(self) -> bytes:
        """
        Attempt to discover the subkey used in the last round of the cipher. The method is expected to succeed with
        probability greater than 50%.
        :return: A guess of the last 2 bytes of the cipher key.
        """
        key_guess = 0

        for approximation in self.APPROXIMATIONS:
            samples = approximation.required_samples()
            while len(self.samples) < samples:
                self._sample()

            results: List[Tuple[int, float]] = []
            for subkey in approximation.subkeys():
                matches = 0
                pairs = list(self.samples.items())[:samples]
                for (plaintext, ciphertext) in pairs:
                    ciphertext = self._reverse_last_round(ciphertext, subkey)
                    if approximation.linear_equivalence_holds(plaintext, ciphertext):
                        matches += 1
                bias = abs(matches - samples / 2) / samples
                results.append((subkey, bias))

            key_guess |= max(results, key=lambda x: x[1])[0]

        return key_guess.to_bytes(Cipher.BLOCK_SIZE, byteorder="big")

    def _sample(self) -> None:
        # Add a new plaintext/ciphertext sample.
        plaintext = os.urandom(Cipher.BLOCK_SIZE)
        ciphertext = self.cipher.encrypt(plaintext)
        plaintext = int.from_bytes(plaintext, byteorder="big")
        ciphertext = int.from_bytes(ciphertext[:Cipher.BLOCK_SIZE], byteorder="big")
        self.samples[plaintext] = ciphertext

    def _reverse_last_round(self, ciphertext: int, subkey: int) -> int:
        # Reverse last cipher round.
        ciphertext ^= subkey
        return self.cipher._substitute(ciphertext, Cipher._S_BOX_INV)
