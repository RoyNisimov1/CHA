import hashlib
import secrets
from .CommonAlgs import CommonAlgs
from .BlackFrog import *
class OAEP:
    @staticmethod
    def repeated_key_xor(plain_text, key):
        return CommonAlgs.repeated_key_xor(plain_text, key)

    @staticmethod
    def oaep_pad(message):
        nonce = secrets.randbits(32)
        nonce = nonce.to_bytes(32, sys.byteorder)
        mm = message + b"\x00" * (32 - len(message))
        G = OAEP.repeated_key_xor(mm, hashlib.sha256(nonce).digest())
        H = OAEP.repeated_key_xor(nonce, hashlib.sha256(G).digest())
        return G + H

    @staticmethod
    def oaep_unpad(message):
        oaep_step2 = message + b'\x00' * (64 - len(message))
        G = oaep_step2[:32]
        H = oaep_step2[32:64]
        nonce = OAEP.repeated_key_xor(H, hashlib.sha256(G).digest())[:32]
        mm = OAEP.repeated_key_xor(G, hashlib.sha256(nonce).digest())
        return mm

    @staticmethod
    def encrypt(msg, n, pub):
        oaep = OAEP.oaep_pad(msg)
        m_int = int.from_bytes(oaep, sys.byteorder)
        ret_int = pow(m_int, pub, n)
        ret_b = ret_int.to_bytes(ret_int.bit_length(), sys.byteorder)
        return ret_b

    @staticmethod
    def decrypt(ciphertext, n, priv):
        rsa_int = int.from_bytes(ciphertext, sys.byteorder)
        oaep_step1 = pow(rsa_int, priv, n)
        return OAEP.oaep_unpad(oaep_step1)

    @staticmethod
    def encrypt_BlackFrog(key: BlackFrogKey, msg: bytes):
        oaep = OAEP.oaep_pad(msg)
        oaep_int = int.from_bytes(oaep, sys.byteorder)
        if oaep_int >= key.n: OAEP.encrypt_BlackFrog(key, msg)
        cipher = BlackFrog.encrypt(key, oaep)
        return cipher

    @staticmethod
    def decrypt_BlackFrog(key: BlackFrogKey, cipher: bytes):
        oaep = BlackFrog.decrypt(key, cipher)
        return OAEP.oaep_unpad(oaep)


