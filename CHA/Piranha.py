import sys
from .CHAF import *
import secrets
from .Modes import *
from .CommonAlgs import CommonAlgs
from .Padding import PKCS7
class Piranha:
    ECB = Modes.ECB
    CBC = Modes.CBC
    CTR = Modes.CTR
    EAA = Modes.EAA
    BlockSize = 64
    _uses_IV = [CTR, CBC]

    @staticmethod
    def repeated_key_xor(plain_text, key):
        return CommonAlgs.repeated_key_xor(plain_text, key)

    def __init__(self, key, mode: int, *args, **kwargs):
        self.mode = Modes(key, mode, *args, **kwargs)
        self.key = key
        self.m = mode
        self.iv = self.mode.iv
        self.args = args
        self.kwargs = kwargs

    def update(self, data: bytes):
        self.mode.update(data)




    @staticmethod
    def split_nth(n: int, line: str):
        return [line[i:i + n] for i in range(0, len(line), n)]

    @staticmethod
    def pad(data: bytes, blockSize=None):
        if blockSize is None: blockSize = Piranha.BlockSize
        return PKCS7(blockSize).pad(data)

    @staticmethod
    def unpad(data: bytes, blockSize=None):
        if blockSize is None: blockSize = Piranha.BlockSize
        return PKCS7(blockSize).unpad(data)

    def encryptionFunction(self, data: bytes, key, *args, **kwargs):
        func = FeistelN.fRAB_with_nonce(key, rep=1, rev=1)
        return FeistelN().DE(data, 4, func, 'e', 's')

    def decryptionFunction(self, data: bytes, key, *args, **kwargs):
        func = FeistelN.fRAB_with_nonce(key, rep=1, rev=1)
        return FeistelN().DE(data, 4, func, 'd', 's')

    def encrypt(self, data: bytes = None, func=None):
        if func is None: func = FeistelN.fRAB_with_nonce(self.key, rep=1, rev=1)
        if data is None: data = self.mode.data
        return self.mode.encrypt(data, self.encryptionFunction)

    def decrypt(self, cipher: bytes, func=None):
        if func is None: func = FeistelN.fRAB_with_nonce(self.key, rep=1, rev=1)
        if cipher is None: cipher = self.mode.data
        return self.mode.decrypt(cipher, self.decryptionFunction)

    def HMAC(self, data: bytes) -> bytes:
        return self.mode.HMAC(data)

    def verify(self, data: bytes, mac: bytes) -> bytes:
        return self.mode.verify(data, mac)


