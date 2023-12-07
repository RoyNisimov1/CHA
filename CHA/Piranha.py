import sys
from .CHAF import *
import secrets
from .Modes import *

class Piranha:
    ECB = 0
    CBC = 1
    CTR = 2
    BlockSize = 64
    _uses_IV = [CTR, CBC]

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
        self.iv = secrets.token_bytes(16)
        if 'iv' in kwargs.keys():
            self.iv = kwargs['iv']
        self.data = b''
        if 'data' in kwargs.keys():
            self.data = Piranha.pad(kwargs['data'], Piranha.BlockSize)
        self.args = args
        self.kwargs = kwargs

    def update(self, data: bytes):
        self.data = data

    def HMAC(self, data: bytes = None, func=None) -> bytes:
        if func is None: func = FeistelN.fRAB_with_nonce(self.key, rep=1, rev=1)
        if data is None: data = self.data
        key = Piranha.repeated_key_xor(self.key, self.iv) if self.mode in Piranha._uses_IV else self.key
        hmac_obj = CHAFHMAC(key, func)
        hmac_obj.update(data)
        mac = hmac_obj.digest()
        return mac

    def verify(self, data: bytes = None, mac=b'', func=None):
        if func is None: func = FeistelN.fRAB_with_nonce(self.key, rep=1, rev=1)
        if data is None: data = self.data
        return self.HMAC(data=data, func=func) == mac


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

    def encrypt(self, data: bytes = None, func=None):
        if func is None: func = FeistelN.fRAB_with_nonce(self.key, rep=1, rev=1)
        if data is None: data = self.data
        data = Piranha.pad(data, Piranha.BlockSize)
        if self.mode == Piranha.CTR:
            repUnit = 16
            dataList = Piranha.split_nth(self.BlockSize, data)
            times = len(dataList)
            if times < repUnit: repUnit = times
            encryptedIVs = []
            for i in range(repUnit):
                bytesI = i.to_bytes(i.bit_length(), sys.byteorder)
                nonce = self.iv + bytesI
                iv = FeistelN().DE(nonce, 4, func, 'e', 's')
                encryptedIVs.append(iv)
            out = [Piranha.repeated_key_xor(Piranha.repeated_key_xor(encryptedIVs[i % len(encryptedIVs)], c), self.key) for i, c in enumerate(dataList)]
            return b''.join(out)
        if self.mode == Piranha.ECB:
            return FeistelN().DE(data, 4, func, 'e', 's')
        if self.mode == Piranha.CBC:
            dataList = Piranha.split_nth(self.BlockSize, data)
            times = len(dataList)
            encrypted = []
            nextXOR = self.iv
            for i in range(times):
                xoredData = Piranha.repeated_key_xor(dataList[i], nextXOR)
                encryptedData = FeistelN().DE(xoredData, 4, func, 'e', 's')
                encrypted.append(encryptedData)
                nextXOR = encryptedData
            return b''.join(encrypted)

    def decrypt(self, cipher: bytes, func=None):
        if func is None: func = FeistelN.fRAB_with_nonce(self.key, rep=1, rev=1)
        if self.mode == Piranha.CTR: return self.encrypt(cipher, func)
        if self.mode == Piranha.ECB:
            return Piranha.unpad(FeistelN().DE(cipher, 4, func, 'd', 's'), Piranha.BlockSize)
        if self.mode == Piranha.CBC:

            dataList = Piranha.split_nth(self.BlockSize, cipher)
            times = len(dataList)
            decrypted = []
            nextXOR = self.iv
            for i in range(times):
                decryptedData = FeistelN().DE(dataList[i], 4, func, 'd', 's')
                xored = Piranha.repeated_key_xor(decryptedData, nextXOR)
                decrypted.append(xored)
                nextXOR = dataList[i]
            return Piranha.unpad(b''.join(decrypted))

class PKCS7(object):
    def __init__(self, block_size):
        self.block_size = block_size

    def pad(self, byte_str: bytes) -> bytes:
        padding_number = self.block_size - len(byte_str) % self.block_size
        if padding_number == self.block_size:
            return byte_str
        padding = chr(padding_number).encode() * padding_number
        return byte_str + padding

    def unpad(self, byte_str: bytes) -> bytes:
        if not byte_str: return byte_str
        if len(byte_str) % self.block_size:
            return byte_str
        padding_number = byte_str[-1]
        if padding_number >= self.block_size:
            return byte_str
        else:
            if all(padding_number == c for c in byte_str[-padding_number:]):
                return byte_str[0:-padding_number]
            else:
                return byte_str
