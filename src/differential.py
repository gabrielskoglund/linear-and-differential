import logging
import os
from abc import ABC, abstractmethod
from collections import defaultdict
from typing import Generator, List, Tuple, Dict

from src.cipher import Cipher


class _DifferentialCharacteristic(ABC):
    @abstractmethod
    def subkeys(self) -> Generator[int, None, None]:
        """
        The subkeys to be checked for this differential characteristic.
        """
        pass

    @abstractmethod
    def input_difference(self) -> int:
        """
        Get the input difference of this differential characteristic.
        """
        pass

    @abstractmethod
    def is_possible_right_pair(self, ciphertext_1: int, ciphertext_2: int) -> bool:
        """
        Check if this pair of ciphertexts is a possible right pair that matches the characteristic.
        """
        pass

    @abstractmethod
    def is_right_pair(self, ciphertext_1: int, ciphertext_2: int) -> bool:
        """
        Check if this pair of ciphertexts is a right pair that matches the characteristic.
        """
        pass

    @abstractmethod
    def required_samples(self) -> int:
        """
        The number of samples required to have a good probability to successfully extract the subkey bits using
        this differential characteristic. Note that each sample is a pair of ciphertexts resulting from a pair of
        plaintext having the output differential associated with this characteristic.
        """
        pass


class _Round5KeyBlock2And4(_DifferentialCharacteristic):
    """
    This is the differential characteristic presented by Heys.

    Trail: Round 1: b -> [S12]
           Round 2: 4 -> [S23]
           Round 3: 2 -> [S32] and 2 -> S[33]
           Round 4: 6 -> [S42] and 6 -> S[44]
    Probability of occurring: 27/1024
    Input difference:  0x0b00
    Output difference: 0x0606
    """

    def subkeys(self) -> Generator[int, None, None]:
        for subkey_bits in range(2 ** 8):
            yield (subkey_bits & 0xf0) << 4 | (subkey_bits & 0xf)

    def input_difference(self) -> int:
        return 0x0b00

    def is_possible_right_pair(self, ciphertext_1: int, ciphertext_2: int) -> bool:
        difference = ciphertext_1 ^ ciphertext_2
        return difference & 0xf0f0 == 0

    def is_right_pair(self, ciphertext_1: int, ciphertext_2: int) -> bool:
        difference = ciphertext_1 ^ ciphertext_2
        return difference == 0x0606

    def required_samples(self) -> int:
        # Note: Heys used 5000 samples, but experiments indicate that 300 are enough to guarantee > 90% success rate
        return 300


class _Round5KeyBlock1And3(_DifferentialCharacteristic):
    """
    Trail: Round 1: 2 -> [S11] and 2 -> [S13]
           Round 2: a -> [S22] and a -> [S24]
           Round 3: 5 -> [S31]
           Round 4: 8 -> [S41] and 8 -> S[43]
    Probability of occurring: 81/16384
    Input difference:  0x2020
    Output difference: 0x8080
    """

    def subkeys(self) -> Generator[int, None, None]:
        for subkey_bits in range(2 ** 8):
            yield (subkey_bits & 0xf0) << 8 | (subkey_bits & 0xf) << 4

    def input_difference(self) -> int:
        return 0x2020

    def is_possible_right_pair(self, ciphertext_1: int, ciphertext_2: int) -> bool:
        difference = ciphertext_1 ^ ciphertext_2
        return difference & 0x0f0f == 0

    def is_right_pair(self, ciphertext_1: int, ciphertext_2: int) -> bool:
        difference = ciphertext_1 ^ ciphertext_2
        return difference == 0x8080

    def required_samples(self) -> int:
        return 1500


class _Round4KeyAllBlocks(_DifferentialCharacteristic):
    """
    Trail: Round 1: 4 -> [S12]
           Round 2: 4 -> [S22] and 4 -> [S23]
           Round 3: 2 -> [S31], 4 -> [S32], 6 -> [S33] 2 -> [S34]
    Probability of occurring: 9/256
    Input difference:  0x0400
    Output difference: 0x2462
    """

    def subkeys(self) -> Generator[int, None, None]:
        for subkey_bits in range(2 ** 16):
            yield subkey_bits

    def input_difference(self) -> int:
        return 0x0400

    def is_possible_right_pair(self, ciphertext_1: int, ciphertext_2: int) -> bool:
        return True

    def is_right_pair(self, ciphertext_1: int, ciphertext_2: int) -> bool:
        difference = ciphertext_1 ^ ciphertext_2
        return difference == 0x2462

    def required_samples(self) -> int:
        return 200


class _Round3KeyAllBlocks(_DifferentialCharacteristic):
    """
    Trail: Round 1: 3 -> [S14]
           Round 2: 1 -> [S21], 1 -> [S22], 1 -> [S23] and 1 -> [S24]
    Probability of occurring: 1/4
    Input difference:  0x0003
    Output difference: 0x1111
    """

    def subkeys(self) -> Generator[int, None, None]:
        for subkey_bits in range(2 ** 16):
            yield subkey_bits

    def input_difference(self) -> int:
        return 0x0003

    def is_possible_right_pair(self, ciphertext_1: int, ciphertext_2: int) -> bool:
        return True

    def is_right_pair(self, ciphertext_1: int, ciphertext_2: int) -> bool:
        difference = ciphertext_1 ^ ciphertext_2
        return difference == 0x1111

    def required_samples(self) -> int:
        return 20


class _Round2KeyAllBlocks(_DifferentialCharacteristic):
    """
    Trail: Round 1: f -> S[11], f -> S[12], f -> S[13], f -> S[14]
    Probability of occurring: 1
    Input difference:  0xffff
    Output difference: 0xffff
    """

    def subkeys(self) -> Generator[int, None, None]:
        for subkey_bits in range(2 ** 16):
            yield subkey_bits

    def input_difference(self) -> int:
        return 0xffff

    def is_possible_right_pair(self, ciphertext_1: int, ciphertext_2: int) -> bool:
        return True

    def is_right_pair(self, ciphertext_1: int, ciphertext_2: int) -> bool:
        difference = ciphertext_1 ^ ciphertext_2
        return difference == 0xffff

    def required_samples(self) -> int:
        # This differential is guaranteed to occur for the right round key, but may also occur for other incorrect
        # round keys, so we must have more than one sample to have a good probability of finding the right round key.
        return 10


class DifferentialAnalyzer:
    """
        The DifferentialAnalyzer class provides functionality for breaking a cipher key using
        differential cryptanalysis.
    """

    CHARACTERISTICS: List[List[_DifferentialCharacteristic]] = [
        [_Round5KeyBlock2And4(), _Round5KeyBlock1And3()],
        [_Round4KeyAllBlocks()],
        [_Round3KeyAllBlocks()],
        [_Round2KeyAllBlocks()]
    ]

    def __init__(self, cipher: Cipher) -> None:
        """
        Create a new DifferentialAnalyzer instance.
        :param cipher: The cipher to attack.
        """
        self.cipher = cipher
        self.samples: Dict[int, List[Tuple[int, int]]] = defaultdict(list)
        self.log = logging.getLogger(__name__)

    def break_key(self) -> bytes:
        """
        Attempt to break the cipher key for the cipher associated with this DifferentialAnalyzer.
        :return: The cipher key.
        :raises: A KeyBreakingException if key breaking fails. This is expected to occur with less than 50% probability.
        """
        round_key_guesses = []

        for round_number, round_characteristics in enumerate(self.CHARACTERISTICS):
            self.log.info(f"Breaking round key for round {5 - round_number}")

            round_key_guess = 0
            for characteristic in round_characteristics:
                round_key_guess |= self._check_characteristic(characteristic, round_key_guesses)

            self.log.info(f"Round key guess for round {5 - round_number}: {round_key_guess:04x}")
            round_key_guesses.insert(0, round_key_guess)

        return self._brute_force_remaining_key_bits(round_key_guesses)

    def _check_characteristic(self, characteristic: _DifferentialCharacteristic, round_key_guesses: List[int]) -> int:
        # Guess a round key (or part thereof) by applying a differential characteristic and finding the key
        # that causes the characteristic to hold the greatest number of times.
        self.log.info(f"Running characteristic {type(characteristic).__name__}")

        in_diff = characteristic.input_difference()
        while len(self.samples[in_diff]) < characteristic.required_samples():
            self.samples[in_diff].append(self._sample(in_diff))

        right_pairs_for_subkey: Dict[int, int] = defaultdict(int)
        for sample in self.samples[in_diff]:
            # For the last round we can use the fact that the expected difference can only have propagated to
            # certain parts of the output if the ciphertext is a right pair. This allows us to quickly
            # exclude pairs that are definitely wrong.
            if not characteristic.is_possible_right_pair(*sample):
                continue

            for subkey in characteristic.subkeys():
                state_1 = self._reverse_cipher(sample[0], [subkey] + round_key_guesses)
                state_2 = self._reverse_cipher(sample[1], [subkey] + round_key_guesses)
                if characteristic.is_right_pair(state_1, state_2):
                    right_pairs_for_subkey[subkey] += 1

        return max(right_pairs_for_subkey.items(), key=lambda x: x[1], default=(0, 0))[0]

    def _brute_force_remaining_key_bits(self, round_key_guesses: List[int]) -> bytes:
        # Brute force the first round key after finding the previous round keys.
        self.log.info("Brute forcing first round key")
        plaintext = b"00"
        ciphertext = self.cipher.encrypt(plaintext)
        round_key_guess_2_to_5 = b"".join(
            [guess.to_bytes(Cipher.BLOCK_SIZE, byteorder="big") for guess in round_key_guesses]
        )
        for first_round_key in range(2 ** 16):
            key_guess = first_round_key.to_bytes(2, byteorder="big") + round_key_guess_2_to_5
            if Cipher(key_guess).encrypt(plaintext) == ciphertext:
                self.log.info(f"Key breaking done. Cipher key: {key_guess.hex().zfill(Cipher.KEY_LENGTH * 2)}")
                return key_guess

        self.log.error("Brute force failed, at least one round key guess was wrong")
        raise KeyBreakingException("Key guessing failed")

    def _sample(self, difference: int) -> Tuple[int, int]:
        # Sample a new pair of ciphertexts by encrypting a pair of plaintexts with the given difference.
        plaintext = os.urandom(Cipher.BLOCK_SIZE)
        ciphertext_1 = int.from_bytes(
            self.cipher.encrypt(plaintext)[:Cipher.BLOCK_SIZE],
            byteorder="big"
        )

        diff_plaintext = int.from_bytes(plaintext, byteorder="big") ^ difference
        diff_plaintext = diff_plaintext.to_bytes(Cipher.BLOCK_SIZE, byteorder="big")
        ciphertext_2 = int.from_bytes(
            self.cipher.encrypt(diff_plaintext)[:Cipher.BLOCK_SIZE],
            byteorder="big"
        )

        return ciphertext_1, ciphertext_2

    def _reverse_cipher(self, ciphertext: int, round_keys: List[int]) -> int:
        # Reverse last cipher round.
        state = ciphertext ^ round_keys[-1]
        state = self.cipher._substitute(state, Cipher._S_BOX_INV)

        # Reverse any remaining rounds with provided round keys
        for round_key in reversed(round_keys[:-1]):
            state ^= round_key
            state = self.cipher._permute(state)
            state = self.cipher._substitute(state, Cipher._S_BOX_INV)

        return state


class KeyBreakingException(Exception):
    """
    Exception indicating that key breaking failed. Key breaking is a probabilistic process, and this exception is
    expected to occur for at most 50% of all differential key breaking attempts.
    """
