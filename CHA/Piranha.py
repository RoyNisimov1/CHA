import sys

from .CHAF import *
import secrets

class Piranha:
    ECB = 0
    CBC = 1
    GCM = 2

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
        if mode == Piranha.GCM or mode == Piranha.CBC:
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

    def encrypt(self, data: bytes):
        if self.mode == Piranha.GCM:
            dataList = Piranha.split_nth(64, data)
            times = len(dataList)
            encrypted = []
            nonce: bytes
            for i in range(times):
                bytesI = i.to_bytes(i.bit_length(), sys.byteorder)
                nonce = self.iv + bytesI
                encryptedNonce = FeistelN().DE(nonce, 8, FeistelN.fRAB_with_nonce(self.key, rep=2), 'e', 's').encode()
                xoredEncryptedNonce = Piranha.repeated_key_xor(encryptedNonce, self.iv)
                encrypted.append(xoredEncryptedNonce)
            out = [Piranha.repeated_key_xor(Piranha.repeated_key_xor(dataList[i], c), self.key) for i, c in enumerate(encrypted)]
            return b''.join(out)
        if self.mode == Piranha.ECB:
            return FeistelN().DE(data, 8, FeistelN.fRAB_with_nonce(self.key, rep=2), 'e', 's').encode()
        if self.mode == Piranha.CBC:
            dataList = Piranha.split_nth(64, data)
            times = len(dataList)
            encrypted = []
            nextXOR = self.iv
            for i in range(times):
                xoredData = Piranha.repeated_key_xor(dataList[i], nextXOR)
                encryptedData = FeistelN().DE(xoredData, 8, FeistelN.fRAB_with_nonce(self.key, rep=2), 'e', 's').encode()
                encrypted.append(encryptedData)
                nextXOR = encryptedData
            return b''.join(encrypted)

    def decrypt(self, cipher: bytes):
        if self.mode == Piranha.GCM: return self.encrypt(cipher)
        if self.mode == Piranha.ECB:
            return FeistelN().DE(cipher.decode(), 8, FeistelN.fRAB_with_nonce(self.key, rep=2), 'd', 's').rstrip(b" ")
        if self.mode == Piranha.CBC:
            cipher = cipher.decode()
            dataList = Piranha.split_nth(128, cipher)
            times = len(dataList)
            decrypted = []
            nextXOR = self.iv
            for i in range(times):
                decryptedData = FeistelN().DE(dataList[i], 8, FeistelN.fRAB_with_nonce(self.key, rep=2), 'd', 's')
                xored = Piranha.repeated_key_xor(decryptedData, nextXOR)
                decrypted.append(xored)
                nextXOR = dataList[i].encode()
            return b''.join(decrypted)
