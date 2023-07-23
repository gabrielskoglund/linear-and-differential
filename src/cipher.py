from typing import List


class Cipher:
    """
    A very basic substitution-permutation cipher.
    """
    KEY_LENGTH = 10
    BLOCK_SIZE = 2

    _S_BOX = [
        0xe, 0x4, 0xd, 0x1,
        0x2, 0xf, 0xb, 0x8,
        0x3, 0xa, 0x6, 0xc,
        0x5, 0x9, 0x0, 0x7
    ]

    _S_BOX_INV = [
        0xe, 0x3, 0x4, 0x8,
        0x1, 0xc, 0xa, 0xf,
        0x7, 0xd, 0x9, 0x6,
        0xb, 0x2, 0x0, 0x5
    ]

    def __init__(self, key: bytes) -> None:
        """
        Initialize a new cipher instance with the given key.
        :param key: a byte sequence of exactly 10 bytes.
        :raises ValueError: if the key given is of incorrect length.
        """
        if len(key) != self.KEY_LENGTH:
            raise ValueError(f"Cipher key must be exactly {self.KEY_LENGTH} bytes long")

        self._key = [int.from_bytes(key[i:i + self.BLOCK_SIZE], byteorder="big")
                     for i in range(0, self.KEY_LENGTH, self.BLOCK_SIZE)]

    def encrypt(self, data: bytes) -> bytes:
        """
        Encrypt an input message using the ECB block cipher mode.
        :param data: The plaintext to encrypt.
        :return: The plaintext encrypted using the cipher key.
        :raises AttributeError: If the Cipher is not correctly initialized with a key.
        """
        if not self._key:
            raise AttributeError("Cipher key not initialized")

        data = self._pad(data)
        blocks = [int.from_bytes(data[i:i + self.BLOCK_SIZE], byteorder="big")
                  for i in range(0, len(data), self.BLOCK_SIZE)]
        ciphertext = b""

        for block in blocks:
            for i in range(3):
                block ^= self._key[i]
                block = self._substitute(block, self._S_BOX)
                block = self._permute(block)
            block ^= self._key[3]
            block = self._substitute(block, self._S_BOX)
            block ^= self._key[4]
            ciphertext += block.to_bytes(length=self.BLOCK_SIZE, byteorder="big")

        return ciphertext

    def decrypt(self, data: bytes) -> bytes:
        """
        Decrypt a ciphertext encrypted using the ECB block cipher mode.
        :param data: The ciphertext to decrypt.
        :return: The ciphertext decrypted using the cipher key.
        :raises AttributeError: If the Cipher is not correctly initialized with a key.
        :raises ValueError: If the ciphertext is incorrectly padded.
        """
        if not self._key:
            raise AttributeError("Cipher key not initialized")

        blocks = [int.from_bytes(data[i:i + self.BLOCK_SIZE], byteorder="big")
                  for i in range(0, len(data), self.BLOCK_SIZE)]
        plaintext = b""

        for block in blocks:
            block ^= self._key[4]
            block = self._substitute(block, self._S_BOX_INV)
            for i in range(3, 0, -1):
                block ^= self._key[i]
                block = self._permute(block)
                block = self._substitute(block, self._S_BOX_INV)
            block ^= self._key[0]
            plaintext += block.to_bytes(length=self.BLOCK_SIZE, byteorder="big")

        return self._unpad(plaintext)

    def _pad(self, data: bytes) -> bytes:
        # We use PKCS#7 padding to bring the plaintext up to the next full block.
        pad_amount = self.BLOCK_SIZE - (len(data) % self.BLOCK_SIZE)
        return data + pad_amount.to_bytes(1, byteorder="big") * pad_amount

    def _unpad(self, data: bytes) -> bytes:
        pad_byte = data[-1]
        if pad_byte not in range(1, self.BLOCK_SIZE + 1):
            raise ValueError("Incorrectly padded ciphertext")
        for i in range(1, pad_byte + 1):
            if data[-i] != pad_byte:
                raise ValueError("Incorrectly padded ciphertext")
        return data[:-pad_byte]

    def _substitute(self, block: int, s_box: List[int]) -> int:
        for i in range(4):
            val = (block >> 4 * i) & 0xf
            block ^= (val ^ s_box[val]) << (4 * i)
        return block

    def _permute(self, block: int) -> int:
        # We use a neat delta swap bit permutation
        # It looks a bit confusing but works nicely
        swp = (block ^ (block >> 3)) & 0x0842  # Bit mask: 0000 1000 0100 0010
        block = block ^ swp ^ (swp << 3)
        swp = (block ^ (block >> 6)) & 0x0084  # Bit mask: 0000 0000 1000 0100
        block = block ^ swp ^ (swp << 6)
        swp = (block ^ (block >> 9)) & 0x0008  # Bit mask: 0000 0000 0000 1000
        return block ^ swp ^ (swp << 9)
