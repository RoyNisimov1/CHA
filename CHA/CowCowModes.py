from .CHAF import *
from .Modes import *
from .Padding import PKCS7
from .CowCow import CowCow
from .OAEP import OAEP
from secrets import token_bytes
class CowCowModes:
    ECB = Modes.ECB
    # CBC = Modes.CBC
    CTR = Modes.CTR
    EAA = Modes.EAA
    BlockSize = 64
    _uses_IV = [CTR, EAA]



    def __init__(self, key, mode: int, *args, **kwargs):
        self.mode = Modes.new(key, mode, *args, **kwargs)
        self.key = key
        self.m = mode
        self.iv = self.mode.iv
        self.args = args
        self.kwargs = kwargs

    def update(self, data: bytes):
        self.mode.update(data)





    @staticmethod
    def pad(data: bytes, blockSize=None) -> bytes:
        return CowCow.pad(data, blockSize)

    @staticmethod
    def unpad(data: bytes, blockSize=None) -> bytes:
        return CowCow.unpad(data, blockSize)

    def encryptionFunction(self, data: bytes, key, *args, **kwargs) -> bytes:
        cipher = CowCow(key)
        data = self.pad(data)
        return cipher.encrypt(data)

    def decryptionFunction(self, data: bytes, key, *args, **kwargs) -> bytes:
        cipher = CowCow(key)
        return cipher.decrypt(data)

    def encrypt(self, data: bytes = None) -> bytes:
        if data is None: data = self.mode.data
        return self.mode.encrypt(data, self.encryptionFunction)

    def decrypt(self, cipher: bytes) -> bytes:
        if cipher is None: cipher = self.mode.data
        if self.mode.mode != Modes.ECB:
            return self.mode.decrypt(cipher, self.encryptionFunction)
        return self.mode.decrypt(cipher, self.decryptionFunction)

    def HMAC(self, data: bytes) -> bytes:
        return self.mode.HMAC(data)

    def verify(self, data: bytes, mac: bytes) -> bytes:
        return self.mode.verify(data, mac)


