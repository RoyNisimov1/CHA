from .CHAF import *
from base64 import b64encode, b64decode


class PEM:
    @staticmethod
    def export_PEM(b: bytes, passcode: bytes, marker: bytes):
        if len(passcode) == 0: passcode = b'\x00'
        obj = FeistelN().DE(b, 8, FeistelN().fRAB_with_nonce(passcode), 'e', 's')
        b = bytes.fromhex(obj)
        obj = b64encode(b)
        out = b"----BEGIN " + marker + b"----\n"
        out += obj
        out += b"----END " + marker + b"----\n"
        return out

    @staticmethod
    def import_PEM(b: bytes, passcode: bytes, marker: bytes):
        if len(passcode) == 0: passcode = b'\x00'
        striped = b[15+len(marker):-1*(13+len(marker))]
        i = b64decode(striped)
        int_i = i.hex()
        return FeistelN().DE(int_i, 8, FeistelN().fRAB_with_nonce(passcode), 'd', 's').rstrip(b' ')

