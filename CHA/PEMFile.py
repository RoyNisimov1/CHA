from .CHAF import *
from base64 import b64encode, b64decode
from .Piranha import Piranha

class PEM:
    @staticmethod
    def split_nth(n, line):
        return [line[i:i + n] for i in range(0, len(line), n)]

    @staticmethod
    def validate(data: bytes) -> bool:
        close_to_open = {b"----END   ": b"----BEGIN "}
        stack = []
        split = data.split(b"\n")
        for d in split:
            if not d.startswith(b"----"):
                continue
            if d[:10] in close_to_open:
                if not stack: return False
                top_element = stack.pop()
                if close_to_open[d[:10]] != top_element:
                    return False
            else:
                stack.append(d[:10])
        return len(stack) == 0



    @staticmethod
    def export_PEM(b: bytes, passcode: bytes, marker: bytes, n=64):
        if not (len(passcode) == 0 or passcode is None):
            cipher = Piranha(key=passcode, mode=Piranha.EAA)
            data = cipher.encrypt(Piranha.pad(b, Piranha.BlockSize))
            b = data
        e = b64encode(b)
        l = PEM.split_nth(n, e)
        out = b"----BEGIN " + marker + b"----\n"
        out += b"\n".join(l)
        out += b"\n----END   " + marker + b"----"

        return out

    @staticmethod
    def import_PEM(b: bytes, passcode: bytes):
        v = PEM.validate(b)
        if not v: raise ValueError("Invalid data!")

        l = b.split(b"\n")
        l.pop(0)
        l.pop(-1)
        i = b64decode(b''.join(l))
        d = i
        if not (len(passcode) == 0 or passcode is None):
            data = i
            cipher = Piranha(key=passcode, mode=Piranha.EAA)
            d = Piranha.unpad(cipher.decrypt(data))
        return d
