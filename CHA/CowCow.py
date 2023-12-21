from .Padding import PKCS7
from .CommonAlgs import CommonAlgs
from .Hashing_Algorithms import Krhash
class CowCow:
    _SBOX = [8, 106, 37, 11, 69, 146, 169, 103, 195, 95, 65, 191, 116, 29, 16, 144, 64, 18, 1, 93, 180, 119, 89, 63, 157, 83, 14, 217, 188, 181, 176, 241, 140, 252, 238, 36, 98, 212, 244, 15, 193, 251, 235, 209, 131, 23, 132, 177, 149, 74, 186, 104, 120, 52, 211, 125, 230, 196, 127, 223, 87, 48, 133, 26, 197, 167, 88, 118, 100, 108, 123, 44, 222, 6, 2, 148, 115, 227, 94, 4, 208, 170, 17, 220, 171, 219, 60, 128, 242, 7, 250, 19, 160, 135, 25, 182, 141, 155, 45, 200, 245, 54, 21, 92, 124, 96, 166, 91, 143, 246, 30, 204, 38, 253, 213, 12, 183, 49, 161, 225, 72, 137, 139, 51, 9, 179, 121, 82, 24, 126, 156, 205, 75, 86, 168, 226, 233, 129, 27, 0, 215, 130, 232, 136, 110, 55, 33, 79, 85, 231, 192, 187, 122, 199, 153, 159, 201, 145, 173, 240, 224, 165, 142, 58, 228, 22, 175, 76, 39, 117, 67, 210, 198, 105, 202, 229, 150, 32, 68, 102, 138, 81, 164, 59, 70, 20, 43, 184, 46, 207, 61, 90, 134, 172, 40, 107, 206, 112, 13, 174, 152, 101, 10, 154, 194, 248, 185, 254, 237, 249, 71, 78, 84, 203, 218, 162, 255, 97, 163, 50, 35, 216, 66, 3, 99, 41, 77, 5, 109, 42, 57, 47, 214, 80, 236, 234, 189, 113, 31, 147, 243, 62, 114, 28, 34, 56, 53, 158, 239, 178, 221, 111, 190, 151, 247, 73]
    _SBOX1 = [42, 80, 151, 115, 82, 230, 193, 249, 58, 156, 15, 161, 64, 23, 164, 177, 73, 76, 171, 44, 5, 128, 22, 38, 152, 187, 119, 196, 198, 88, 155, 94, 114, 179, 223, 142, 83, 244, 254, 133, 37, 228, 100, 19, 36, 210, 226, 7, 206, 24, 252, 145, 127, 221, 131, 194, 147, 182, 233, 29, 186, 110, 59, 14, 47, 146, 139, 189, 92, 176, 104, 49, 61, 90, 208, 220, 159, 250, 123, 54, 174, 148, 109, 153, 18, 213, 178, 6, 169, 89, 205, 122, 242, 48, 185, 101, 28, 180, 202, 217, 40, 207, 56, 85, 57, 144, 172, 98, 209, 162, 107, 32, 96, 184, 166, 195, 95, 68, 27, 245, 126, 222, 229, 46, 168, 199, 116, 140, 150, 97, 227, 21, 224, 45, 16, 129, 31, 251, 78, 53, 204, 240, 241, 12, 225, 4, 60, 134, 84, 234, 26, 246, 106, 214, 203, 253, 138, 212, 13, 136, 25, 165, 247, 79, 215, 188, 55, 120, 43, 111, 118, 124, 181, 93, 113, 52, 132, 170, 50, 117, 67, 141, 125, 143, 86, 243, 91, 41, 197, 1, 238, 232, 63, 51, 175, 255, 121, 183, 87, 167, 160, 216, 39, 72, 248, 201, 11, 112, 158, 77, 105, 75, 235, 239, 108, 236, 218, 231, 9, 190, 103, 70, 66, 200, 211, 33, 81, 62, 71, 163, 35, 10, 102, 191, 17, 69, 2, 0, 99, 149, 157, 65, 30, 74, 8, 135, 130, 34, 237, 3, 154, 192, 219, 173, 20, 137]
    _SBOX2 = [143, 36, 95, 197, 211, 149, 168, 10, 158, 83, 173, 198, 230, 157, 226, 204, 208, 170, 85, 97, 202, 210, 233, 191, 12, 42, 14, 219, 19, 220, 94, 176, 123, 212, 145, 239, 60, 100, 229, 107, 156, 118, 185, 209, 69, 194, 115, 43, 120, 3, 40, 96, 63, 137, 87, 39, 153, 162, 50, 54, 237, 111, 240, 151, 253, 216, 160, 180, 81, 86, 215, 222, 62, 203, 192, 127, 98, 8, 17, 159, 23, 213, 144, 140, 187, 71, 113, 68, 231, 25, 44, 147, 135, 37, 49, 163, 77, 186, 252, 129, 46, 121, 195, 207, 108, 90, 167, 74, 241, 106, 78, 193, 61, 169, 132, 45, 114, 248, 34, 166, 32, 80, 35, 15, 142, 218, 64, 214, 102, 122, 255, 126, 1, 11, 245, 196, 224, 2, 112, 70, 84, 141, 206, 109, 22, 228, 227, 28, 148, 93, 52, 250, 164, 251, 9, 4, 244, 128, 82, 125, 199, 181, 124, 92, 184, 73, 174, 103, 130, 24, 59, 200, 172, 33, 101, 225, 182, 254, 47, 27, 5, 146, 178, 79, 72, 13, 20, 51, 116, 91, 238, 201, 65, 223, 190, 31, 232, 177, 138, 48, 38, 236, 235, 55, 7, 175, 16, 41, 134, 189, 221, 110, 243, 217, 165, 67, 183, 21, 205, 53, 188, 99, 66, 171, 56, 105, 29, 6, 57, 26, 119, 88, 155, 76, 249, 133, 154, 58, 136, 150, 30, 0, 234, 117, 131, 247, 246, 161, 242, 75, 179, 18, 152, 104, 139, 89]
    _SBOXES = [_SBOX, _SBOX1, _SBOX2]
    _PBOX = {0: 35, 1: 56, 2: 16, 3: 2, 4: 21, 5: 57, 6: 37, 7: 61, 8: 38, 9: 30, 10: 36, 11: 48, 12: 45, 13: 55, 14: 50, 15: 9, 16: 7, 17: 58, 18: 52, 19: 28, 20: 18, 21: 42, 22: 24, 23: 25, 24: 19, 25: 22, 26: 23, 27: 0, 28: 39, 29: 10, 30: 34, 31: 59, 32: 13, 33: 43, 34: 31, 35: 17, 36: 53, 37: 32, 38: 20, 39: 62, 40: 1, 41: 49, 42: 41, 43: 12, 44: 51, 45: 60, 46: 40, 47: 54, 48: 3, 49: 14, 50: 46, 51: 27, 52: 63, 53: 29, 54: 5, 55: 8, 56: 15, 57: 47, 58: 44, 59: 33, 60: 6, 61: 11, 62: 26, 63: 4}
    _PBOX2 = {0: 33, 1: 12, 2: 1, 3: 16, 4: 58, 5: 8, 6: 19, 7: 48, 8: 54, 9: 42, 10: 29, 11: 40, 12: 27, 13: 0, 14: 30, 15: 47, 16: 45, 17: 10, 18: 61, 19: 49, 20: 62, 21: 26, 22: 57, 23: 15, 24: 18, 25: 24, 26: 22, 27: 39, 28: 35, 29: 2, 30: 52, 31: 3, 32: 20, 33: 13, 34: 5, 35: 6, 36: 55, 37: 17, 38: 11, 39: 50, 40: 9, 41: 37, 42: 4, 43: 21, 44: 38, 45: 41, 46: 63, 47: 43, 48: 56, 49: 7, 50: 28, 51: 25, 52: 46, 53: 59, 54: 34, 55: 14, 56: 23, 57: 32, 58: 60, 59: 51, 60: 36, 61: 31, 62: 53, 63: 44}
    _PBOX3 = {0: 17, 1: 59, 2: 3, 3: 36, 4: 47, 5: 45, 6: 5, 7: 18, 8: 13, 9: 51, 10: 19, 11: 11, 12: 58, 13: 57, 14: 33, 15: 24, 16: 34, 17: 4, 18: 14, 19: 63, 20: 26, 21: 27, 22: 61, 23: 48, 24: 30, 25: 15, 26: 50, 27: 8, 28: 23, 29: 1, 30: 46, 31: 40, 32: 55, 33: 31, 34: 6, 35: 37, 36: 39, 37: 20, 38: 62, 39: 12, 40: 21, 41: 56, 42: 42, 43: 10, 44: 49, 45: 44, 46: 0, 47: 22, 48: 7, 49: 2, 50: 25, 51: 16, 52: 54, 53: 35, 54: 29, 55: 41, 56: 53, 57: 43, 58: 28, 59: 52, 60: 60, 61: 32, 62: 9, 63: 38}

    _PBOXES = [_PBOX, _PBOX2, _PBOX3]
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
    def _make_keys(key) -> list:
        l = []
        current = key
        for i in range(16):
            current = Krhash.Krhash(current)[:32]
            l.append(current)
        return l

    def __init__(self, key):
        assert len(key) == self.KeyLength
        self.keys = self._make_keys(key)
        self.key = key

    def switchA(self, i: int, index=1) -> int:
        return self._SBOXES[index % len(self._SBOXES)][i]

    def switchB(self, i: int, index=1) -> int:
        new_boxes = self._SBOXES.copy()
        new_boxes.reverse()
        index = new_boxes[index % len(self._SBOXES)].index(i)
        return index

    def per(self, data, i=1):
        d = self._PBOXES[i % len(self._PBOXES)]
        out = [0] * len(d)
        for i in range(len(out)):
            out[i] = data[d[i]]
        return bytes(out)

    def unper(self, data, i=1):
        new_boxes = self._PBOXES.copy()
        new_boxes.reverse()
        d = new_boxes[i % len(self._PBOXES)]
        out = [0] * len(d)
        for i in range(len(out)):
            index = list(d.keys())[list(d.values()).index(i)]
            out[i] = data[index]
        return bytes(out)

    def R(self, data: bytes, i: int = 1) -> bytes:
        half1 = data[:len(data) // 2]
        half2 = data[len(data) // 2:]
        data = half2 + half1
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
        half1 = bytes(half1)
        half2 = bytes(half2)
        data = half1 + half2
        data = list(data)
        data = self.unper(data)
        data = list(data)
        for j, b in enumerate(data):
            data[j] = self.switchB(b)
        data = self.unper(data)
        half1 = data[:len(data) // 2]
        half2 = data[len(data) // 2:]
        data = half2 + half1
        return bytes(data)

    def _shift_left(self, l: list, num: int) -> list:
        l = l.copy()
        for i in range(num):
            l.append(l.pop(0))
        return l.copy()

    def _shift_right(self, l: list, num: int) -> list:
        l = l.copy()
        for i in range(num):
            l.insert(0, l.pop(-1))
        return l.copy()



    @staticmethod
    def pad(data: bytes, blockSize=None) -> bytes:
        if blockSize is None: blockSize = CowCow.BlockSize
        return PKCS7(blockSize).pad(data)

    @staticmethod
    def unpad(data: bytes, blockSize=None) -> bytes:
        if blockSize is None: blockSize = CowCow.BlockSize
        return PKCS7(blockSize).unpad(data)

    def encrypt(self, plaintext: bytes) -> bytes:

        plaintext = CowCow.repeated_key_xor(plaintext, self.key)
        def e(plaintext: bytes):
            keys = self.keys
            cipher = list(plaintext)
            s = sum(cipher)
            cipher = self._shift_right(cipher, s % 256)
            key = self.key
            for i in range(16):
                cipher = self.R(cipher, i)
                cipher = list(CowCow.repeated_key_xor(cipher, keys[i % len(keys)]))
                if i % 3 == 0:
                    cipher = cipher[::-1]
                if i % 7 == 0:
                    key = key[::-1]
            cipher = cipher[::-1]
            cipher = list(CowCow.repeated_key_xor(cipher, self.key))
            cipher = self._shift_right(cipher, 7)
            return bytes(cipher)

        pts = CommonAlgs.split_nth(self.BlockSize, plaintext)
        out = []
        for pt in pts:
            to_append = e(pt)
            out.append(to_append)
        out = b"".join(out)
        out = self.repeated_key_xor(out, [(self.key[-1] + 1) % 256])
        return out


    def decrypt(self, cipher: bytes) -> bytes:
        def d(cipher):
            key = self.key
            keys = self.keys[::-1]
            cipher = self._shift_left(list(cipher), 7)
            cipher = list(CowCow.repeated_key_xor(cipher, self.key))
            cipher = cipher[::-1]
            plaintext = list(cipher)

            for i in range(16):
                if i % 3 == 0:
                    plaintext = plaintext[::-1]
                if i % 7 == 0:
                    key = key[::-1]
                plaintext = list(CowCow.repeated_key_xor(plaintext, keys[i % len(keys)]))
                plaintext = list(self.InvR(plaintext, i))
            s = sum(plaintext)
            plaintext = self._shift_left(plaintext, s % 256)
            return bytes(plaintext)

        cipher = self.repeated_key_xor(cipher, [(self.key[-1] + 1) % 256])
        pts = CommonAlgs.split_nth(self.BlockSize, cipher)
        out = []
        for pt in pts:
            to_append = d(pt)

            out.append(to_append)
        pt = b"".join(out)
        pt = CowCow.repeated_key_xor(pt, self.key)

        return pt