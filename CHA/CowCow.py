from . import PKCS7
from .CommonAlgs import CommonAlgs
class CowCow:
    _SBOX = [8, 106, 37, 11, 69, 146, 169, 103, 195, 95, 65, 191, 116, 29, 16, 144, 64, 18, 1, 93, 180, 119, 89, 63, 157, 83, 14, 217, 188, 181, 176, 241, 140, 252, 238, 36, 98, 212, 244, 15, 193, 251, 235, 209, 131, 23, 132, 177, 149, 74, 186, 104, 120, 52, 211, 125, 230, 196, 127, 223, 87, 48, 133, 26, 197, 167, 88, 118, 100, 108, 123, 44, 222, 6, 2, 148, 115, 227, 94, 4, 208, 170, 17, 220, 171, 219, 60, 128, 242, 7, 250, 19, 160, 135, 25, 182, 141, 155, 45, 200, 245, 54, 21, 92, 124, 96, 166, 91, 143, 246, 30, 204, 38, 253, 213, 12, 183, 49, 161, 225, 72, 137, 139, 51, 9, 179, 121, 82, 24, 126, 156, 205, 75, 86, 168, 226, 233, 129, 27, 0, 215, 130, 232, 136, 110, 55, 33, 79, 85, 231, 192, 187, 122, 199, 153, 159, 201, 145, 173, 240, 224, 165, 142, 58, 228, 22, 175, 76, 39, 117, 67, 210, 198, 105, 202, 229, 150, 32, 68, 102, 138, 81, 164, 59, 70, 20, 43, 184, 46, 207, 61, 90, 134, 172, 40, 107, 206, 112, 13, 174, 152, 101, 10, 154, 194, 248, 185, 254, 237, 249, 71, 78, 84, 203, 218, 162, 255, 97, 163, 50, 35, 216, 66, 3, 99, 41, 77, 5, 109, 42, 57, 47, 214, 80, 236, 234, 189, 113, 31, 147, 243, 62, 114, 28, 34, 56, 53, 158, 239, 178, 221, 111, 190, 151, 247, 73]
    _PBOX = {0: 35, 1: 56, 2: 16, 3: 2, 4: 21, 5: 57, 6: 37, 7: 61, 8: 38, 9: 30, 10: 36, 11: 48, 12: 45, 13: 55, 14: 50, 15: 9, 16: 7, 17: 58, 18: 52, 19: 28, 20: 18, 21: 42, 22: 24, 23: 25, 24: 19, 25: 22, 26: 23, 27: 0, 28: 39, 29: 10, 30: 34, 31: 59, 32: 13, 33: 43, 34: 31, 35: 17, 36: 53, 37: 32, 38: 20, 39: 62, 40: 1, 41: 49, 42: 41, 43: 12, 44: 51, 45: 60, 46: 40, 47: 54, 48: 3, 49: 14, 50: 46, 51: 27, 52: 63, 53: 29, 54: 5, 55: 8, 56: 15, 57: 47, 58: 44, 59: 33, 60: 6, 61: 11, 62: 26, 63: 4}
    BlockSize = 64
    KeyLength = 32

    @staticmethod
    def repeated_key_xor(plain_text, key) -> bytes:
        pt = plain_text
        len_key = len(key)
        encoded = []

        for i in range(0, len(pt)):
            encoded.append(pt[i] ^ key[i % len_key])
        return bytes(encoded)



    @staticmethod
    def _make_keys(key) -> bytes and bytes and bytes and bytes:
        first = b'\x5c\x44'
        second = b'\x3fkey'
        third = b'\xeaexpansion'
        fourth = b'\x77fourth'
        first_key = CowCow.repeated_key_xor(key, first)
        second_key = CowCow.repeated_key_xor(key, second)
        third_key = CowCow.repeated_key_xor(key, third)
        fourth_key = CowCow.repeated_key_xor(key, fourth)
        return first_key, second_key, third_key, fourth_key

    def __init__(self, key):
        assert len(key) == self.KeyLength
        self.first_key, self.second_key, self.third_key, self.fourth_key = self._make_keys(key)
        self.key = key

    def switchA(self, i: int) -> int:
        return self._SBOX[i]

    def switchB(self, i: int) -> int:
        index = self._SBOX.index(i)
        return index

    def per(self, data):
        d = self._PBOX
        out = [0] * len(d)
        for i in range(len(out)):
            out[i] = data[d[i]]
        return bytes(out)

    def unper(self, data):
        d = self._PBOX
        out = [0] * len(d)
        for i in range(len(out)):
            index = list(d.keys())[list(d.values()).index(i)]
            out[i] = data[index]
        return bytes(out)

    def R(self, data: bytes, i: int = 1) -> bytes:
        data = self.per(data)
        data = list(data)
        for j, b in enumerate(data):
            data[j] = self.switchA(b)
        data = self.per(data)
        half1 = data[:len(data)//2]
        half2 = data[len(data)//2:]
        n = half2 + half1
        if i % 3 == 0:
            n = self.per(n)
        return n

    def InvR(self, data: bytes, i: int = 1) -> bytes:
        if i % 3 == 0:
            data = self.unper(data)
        half1 = data[len(data) // 2:]
        half2 = data[:len(data) // 2]
        data = half1 + half2
        data = self.unper(data)
        data = list(data)
        for j, b in enumerate(data):
            data[j] = self.switchB(b)
        data = self.unper(data)
        return bytes(data)

    @staticmethod
    def pad(data: bytes, blockSize=None) -> bytes:
        if blockSize is None: blockSize = CowCow.BlockSize
        return PKCS7(blockSize).pad(data)

    @staticmethod
    def unpad(data: bytes, blockSize=None) -> bytes:
        if blockSize is None: blockSize = CowCow.BlockSize
        return PKCS7(blockSize).unpad(data)

    def encrypt(self, plaintext: bytes) -> bytes:
        plaintext = plaintext[:64]
        plaintext = self.pad(plaintext)
        def e(plaintext: bytes):
            keys = [self.first_key, self.second_key, self.third_key, self.fourth_key]
            cipher = list(plaintext)
            key = self.key
            for i in range(64):
                cipher = self.R(cipher, i)
                cipher = list(CowCow.repeated_key_xor(cipher, keys[i % len(keys)]))
                cipher = list(CowCow.repeated_key_xor(cipher, key))
                if i % 3 == 0:
                    cipher = cipher[::-1]
                if i % 7 == 0:
                    key = key[::-1]
            cipher = cipher[::-1]
            cipher = list(CowCow.repeated_key_xor(cipher, self.key))
            return bytes(cipher)

        pts = CommonAlgs.split_nth(self.BlockSize, plaintext)
        out = []
        for pt in pts:
            out.append(e(pt))
        return b"".join(out)


    def decrypt(self, cipher: bytes) -> bytes:
        def d(cipher):
            key = self.key
            keys = [self.first_key, self.second_key, self.third_key, self.fourth_key][::-1]
            cipher = list(CowCow.repeated_key_xor(cipher, self.key))
            cipher = cipher[::-1]
            plaintext = list(cipher)

            for i in range(64):
                if i % 3 == 0:
                    plaintext = plaintext[::-1]
                if i % 7 == 0:
                    key = key[::-1]
                plaintext = list(CowCow.repeated_key_xor(plaintext, key))
                plaintext = list(CowCow.repeated_key_xor(plaintext, keys[i % len(keys)]))
                plaintext = list(self.InvR(plaintext, i))
            return bytes(plaintext)

        pts = CommonAlgs.split_nth(self.BlockSize, cipher)
        out = []
        for pt in pts:
            out.append(d(pt))
        pt = b"".join(out)
        return pt