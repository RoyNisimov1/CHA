from .CHAF import *
from base64 import b64encode, b64decode
from .Piranha import Piranha

class PEM:
    @staticmethod
    def split_nth(n, line):
        return [line[i:i + n] for i in range(0, len(line), n)]

    @staticmethod
    def export_PEM(b: bytes, passcode: bytes, marker: bytes, n=64):
        if not (len(passcode) == 0 or passcode is None):
            cipher = Piranha(key=passcode, mode=Piranha.CTR)
            data = cipher.encrypt(Piranha.pad(b, Piranha.BlockSize))
            b = cipher.iv + data
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
        d = i
        if not (len(passcode) == 0 or passcode is None):
            iv = i[:16]
            data = i[16:]
            cipher = Piranha(key=passcode, mode=Piranha.CTR, iv=iv)
            d = Piranha.unpad(cipher.decrypt(data))
        return d
