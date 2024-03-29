from __future__ import annotations

import hmac
import secrets
from .CommonAlgs import CommonAlgs
from .Padding import PKCS7
class Modes:
    ECB = 0
    CBC = 1
    CTR = 2
    EAA = 3
    _uses_IV = [CTR, CBC]
    BlockSize = 64

    _registry = {}


    @staticmethod
    def new(key: bytes = None, prefix:int=0, *args, **kwargs) -> Modes:
        return Modes(key, prefix, *args, **kwargs)

    def __init_subclass__(cls, prefix, **kwargs):
        super().__init_subclass__(**kwargs)
        cls._registry[prefix] = cls

    def __new__(cls, key=None, prefix=0, *args, **kwargs):
        subclass = cls._registry[prefix]
        obj = object.__new__(subclass)
        obj.key = key
        obj.mode = prefix
        obj.iv = secrets.token_bytes(16)
        if 'iv' in kwargs.keys():
            obj.iv = kwargs['iv']
        obj.BlockSize = 64
        if 'BlockSize' in kwargs.keys():
            obj.BlockSize = kwargs['BlockSize']
        obj.data = b''
        if 'data' in kwargs.keys():
            obj.data = PKCS7(obj.BlockSize).pad(kwargs['data'])
        obj.args = args
        obj.kwargs = kwargs
        obj.key = key
        return obj


    @staticmethod
    def repeated_key_xor(plain_text, key) -> bytes:
        return CommonAlgs.repeated_key_xor(plain_text, key)

    def HMAC(self, data: bytes) -> bytes:
        return hmac.new(self.key + self.iv, data, digestmod="sha512").digest()

    def verify(self, data: bytes, mac: bytes) -> bytes:
        return hmac.compare_digest(hmac.new(self.key + self.iv, data, digestmod="sha512").digest(), mac)

    @staticmethod
    def split_nth(n: int, line: str or bytes) -> str or bytes:
        return [line[i:i + n] for i in range(0, len(line), n)]


    def pad(self, data: bytes) -> bytes:
        return PKCS7(self.BlockSize).pad(data)

    @staticmethod
    def unpad(self, data: bytes) -> bytes:
        return PKCS7(self.BlockSize).unpad(data)

    def encrypt(self, data: bytes, func, *args, **kwargs) -> bytes:
        raise NotImplementedError

    def update(self, data: bytes)  -> None:
        self.data = data

    def decrypt(self, cipher: bytes, func, *args, **kwargs) -> bytes:
        raise NotImplementedError

class ModesCTR(Modes, prefix=Modes.CTR):
    def encrypt(self, data: bytes, func, *args, **kwargs) -> bytes:
        if data is None: data = self.data
        data = self.pad(data)
        repUnit = 16
        if 'n' in kwargs:
            repUnit = kwargs['n']
        dataList = self.split_nth(self.BlockSize, data)
        times = len(dataList)
        if times < repUnit: repUnit = times
        encryptedIVs = []
        for i in range(1, repUnit+1):
            nonce = self.iv + bytes([i])
            iv = func(nonce, self.key, *args, **kwargs)
            encryptedIVs.append(iv)
        out = [self.repeated_key_xor(self.repeated_key_xor(encryptedIVs[i % len(encryptedIVs)], c), self.key)
               for i, c in enumerate(dataList)]
        return b''.join(out)

    def decrypt(self, cipher: bytes, func, *args, **kwargs) -> bytes:
        return self.encrypt(cipher, func, *args, **kwargs)

class ModesCBC(Modes, prefix=Modes.CBC):
    def encrypt(self, data: bytes, func, *args, **kwargs) -> bytes:
        if data is None: data = self.data
        dataList = self.split_nth(self.BlockSize, data)
        times = len(dataList)
        encrypted = []
        nextXOR = self.iv
        for i in range(times):
            xoredData = self.repeated_key_xor(dataList[i], nextXOR)
            encryptedData = func(xoredData, self.key, *args, **kwargs)
            encrypted.append(encryptedData)
            nextXOR = encryptedData
        return self.repeated_key_xor(b''.join(encrypted), self.key)

    def decrypt(self, cipher: bytes, func, *args, **kwargs) -> bytes:
        cipher = self.repeated_key_xor(cipher, self.key)
        dataList = Modes.split_nth(self.BlockSize, cipher)
        times = len(dataList)
        decrypted = []
        nextXOR = self.iv
        for i in range(times):
            decryptedData = func(dataList[i], self.key, *args, **kwargs)
            xored = Modes.repeated_key_xor(decryptedData, nextXOR)
            decrypted.append(xored)
            nextXOR = dataList[i]
        return b''.join(decrypted)

class ModesECB(Modes, prefix=Modes.ECB):
    def encrypt(self, data: bytes, func, *args, **kwargs) -> bytes:
        ra = []
        ml = Modes.split_nth(self.BlockSize, data)
        for i in ml:
            ra.append(func(i, self.key, *args, **kwargs))
        return b"".join(ra)

    def decrypt(self, cipher: bytes, func, *args, **kwargs) -> bytes:
        ra1 = []
        message = Modes.split_nth(self.BlockSize, cipher)
        for e in message:
            ra1.append(func(e, self.key, *args, **kwargs))
        return b''.join(ra1)


class ModesEAA(Modes, prefix=Modes.EAA):

    def encrypt(self, data: bytes, func, *args, **kwargs) -> bytes:
        cipher = Modes(self.key, Modes.CTR, data=data, iv=self.iv)
        d = cipher.encrypt(data, func)
        hmac = cipher.HMAC(data)
        self.iv = secrets.token_bytes(16)
        return hmac + cipher.iv + d

    def decrypt(self, cipher: bytes, func, *args, **kwargs) -> bytes:
        hmac = cipher[:64]
        iv = cipher[64:80]
        data = cipher[80:]
        cipher = Modes(self.key, Modes.CTR, data=data, iv=iv)
        pt = cipher.decrypt(data, func)
        v = cipher.verify(pt, hmac)
        if not v: raise ValueError("HMACs don't match!")
        return pt