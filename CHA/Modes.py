import sys
import secrets

class Modes:
    ECB = 0
    CBC = 1
    CTR = 2

    BlockSize = 64

    @staticmethod
    def repeated_key_xor(plain_text, key):
        pt = plain_text
        len_key = len(key)
        encoded = []

        for i in range(0, len(pt)):
            encoded.append(pt[i] ^ key[i % len_key])
        return bytes(encoded)

    def __init__(self, key, mode: int, *args, **kwargs):
        self.key = key
        self.mode = mode
        if mode == Modes.CTR or mode == Modes.CBC:
            if 'iv' not in kwargs.keys():
                self.iv = secrets.token_hex(9)[:16].encode()
            else:
                self.iv = kwargs['iv']
        self.args = args
        self.kwargs = kwargs


    @staticmethod
    def split_nth(n: int, line: str):
        return [line[i:i + n] for i in range(0, len(line), n)]

    @staticmethod
    def pad(data: bytes, blockSize: int):
        l = len(data)
        to_add = blockSize - (l % blockSize)
        return data + b' ' * to_add

    @staticmethod
    def unpad(data: bytes):
        return data.rstrip(b" ")

    def encrypt(self, data: bytes, func):
        if self.mode == Modes.CTR:
            dataList = Modes.split_nth(64, data)
            times = len(dataList)
            encrypted = []
            nonce: bytes
            for i in range(times):
                bytesI = i.to_bytes(i.bit_length(), sys.byteorder)
                nonce = self.iv + bytesI
                encryptedNonce = func(nonce)
                xoredEncryptedNonce = Modes.repeated_key_xor(encryptedNonce, self.iv)
                encrypted.append(xoredEncryptedNonce)
            out = [Modes.repeated_key_xor(Modes.repeated_key_xor(dataList[i], c), self.key) for i, c in enumerate(encrypted)]
            return b''.join(out)
        if self.mode == Modes.ECB:
            ra = []
            ml = Modes.split_nth(data, 64)
            for i in ml:
                ra.append(func(i))
            return b"".join(ra)
        if self.mode == Modes.CBC:
            dataList = Modes.split_nth(64, data)
            times = len(dataList)
            encrypted = []
            nextXOR = self.iv
            for i in range(times):
                xoredData = Modes.repeated_key_xor(dataList[i], nextXOR)
                encryptedData = func(xoredData)
                encrypted.append(encryptedData)
                nextXOR = encryptedData
            return b''.join(encrypted)

    def decrypt(self, cipher: bytes, func):
        if self.mode == Modes.CTR: return self.encrypt(cipher, func)
        if self.mode == Modes.ECB:
            ra1 = []
            message = Modes.split_nth(cipher, 128)
            for e in message:
                ra1.append(func(e))
            return b''.join(ra1)
        if self.mode == Modes.CBC:
            cipher = cipher.decode()
            dataList = Modes.split_nth(128, cipher)
            times = len(dataList)
            decrypted = []
            nextXOR = self.iv
            for i in range(times):
                decryptedData = func(dataList[i])
                xored = Modes.repeated_key_xor(decryptedData, nextXOR)
                decrypted.append(xored)
                nextXOR = dataList[i].encode()
            return b''.join(decrypted)
