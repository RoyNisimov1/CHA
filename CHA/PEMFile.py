from .CHAF import *
from base64 import b64encode, b64decode


class PEM:
    @staticmethod
    def export_PEM(b: bytes, passcode: bytes, marker: bytes):
        if len(passcode) == 0: passcode = b'\x00'
        obj = FeistelN().DE(b, 1, FeistelN().fRAB_with_nonce(passcode), 'e', 's')
        b = bytes.fromhex(obj)
        obj = b64encode(b)
        out = b"----BEGIN " + marker + b"----\n"
        out += obj
        out += b"\n----END " + marker + b"----"
        return out

    @staticmethod
    def import_PEM(b: bytes, passcode: bytes, marker: bytes):
        if len(passcode) == 0: passcode = b'\x00'
        striped = b[15+len(marker):-1*(13+len(marker))]
        i = b64decode(striped)
        int_i = i.hex()
        return FeistelN().DE(int_i, 1, FeistelN().fRAB_with_nonce(passcode), 'd', 's').rstrip(b' ')

