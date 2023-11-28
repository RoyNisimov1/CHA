from .CHAF import *
from base64 import b64encode, b64decode


class PEM:
    @staticmethod
    def split_nth(n, line):
        return [line[i:i + n] for i in range(0, len(line), n)]

    @staticmethod
    def export_PEM(b: bytes, passcode: bytes, marker: bytes, n=16):
        if not (len(passcode) == 0 or passcode is None):
            obj = FeistelN().DE(b, 8, FeistelN().fRAB_with_nonce(passcode, rep=2), 'e', 's')
            b = bytes.fromhex(obj)
        e = b64encode(b)
        l = PEM.split_nth(n, e)
        out = b"----BEGIN " + marker + b"----\n"
        out += b"\n".join(l)
        out += b"\n----END " + marker + b"----"

        return out

    @staticmethod
    def import_PEM(b: bytes, passcode: bytes):
        l = b.split(b"\n")
        l.pop(0)
        l.pop(-1)
        i = b64decode(b''.join(l))
        int_i = i.hex()
        d = i
        if not (len(passcode) == 0 or passcode is None):
            d = FeistelN().DE(int_i, 8, FeistelN().fRAB_with_nonce(passcode, rep=2), 'd', 's').rstrip(b' ').replace(b"\n", b"")
        return d
