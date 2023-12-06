import sys
import secrets
from .Piranha import *
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
            if 'BlockSize' not in kwargs.keys():
                self.BlockSize = 64
            else:
                self.BlockSize = kwargs['BlockSize']
        self.args = args
        self.kwargs = kwargs


    @staticmethod
    def split_nth(n: int, line: str or bytes):
        return [line[i:i + n] for i in range(0, len(line), n)]


    def pad(self, data: bytes):
        return PKCS7(self.BlockSize).pad(data)

    @staticmethod
    def unpad(self, data: bytes):
        return PKCS7(self.BlockSize).unpad(data)

    def encrypt(self, data: bytes, func):
        if self.mode == Modes.CTR:
            repUnit = 16
            dataList = Piranha.split_nth(self.BlockSize, data)
            times = len(dataList)
            if times < repUnit: repUnit = times
            encryptedIVs = []
            for i in range(repUnit):
                bytesI = i.to_bytes(i.bit_length(), sys.byteorder)
                nonce = self.iv + bytesI
                iv = func(nonce, self.key)
                encryptedIVs.append(iv)
            out = [Piranha.repeated_key_xor(dataList[i % len(encryptedIVs)], c) for i, c in enumerate(encryptedIVs)]
            return b''.join(out)
        if self.mode == Modes.ECB:
            ra = []
            ml = Modes.split_nth(self.BlockSize, data)
            for i in ml:
                ra.append(func(i, self.key))
            return b"".join(ra)
        if self.mode == Modes.CBC:
            dataList = Modes.split_nth(self.BlockSize, data)
            times = len(dataList)
            encrypted = []
            nextXOR = self.iv
            for i in range(times):
                xoredData = Modes.repeated_key_xor(dataList[i], nextXOR)
                encryptedData = func(xoredData, self.key)
                encrypted.append(encryptedData)
                nextXOR = encryptedData
            return b''.join(encrypted)

    def decrypt(self, cipher: bytes, func):
        if self.mode == Modes.CTR: return self.encrypt(cipher, func)
        if self.mode == Modes.ECB:
            ra1 = []
            message = Modes.split_nth(self.BlockSize, cipher)
            for e in message:
                ra1.append(func(e, self.key))
            return b''.join(ra1)
        if self.mode == Modes.CBC:
            cipher = cipher
            dataList = Modes.split_nth(self.BlockSize, cipher)
            times = len(dataList)
            decrypted = []
            nextXOR = self.iv
            for i in range(times):
                decryptedData = func(dataList[i], self.key)
                xored = Modes.repeated_key_xor(decryptedData, nextXOR)
                decrypted.append(xored)
                nextXOR = dataList[i]
            return b''.join(decrypted)
