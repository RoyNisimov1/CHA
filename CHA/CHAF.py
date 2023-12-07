from .CommonAlgs import CommonAlgs
from .Hashing_Algorithms import *
class Block:
    def __init__(self, value: str):
        self.value = value

    def get_value(self):
        return self.value

class FeistelN:
    def __init__(self, n_bits=64):
        self.n_bits = n_bits

    @staticmethod
    def repeated_key_xor(plain_text, key):
        return CommonAlgs.repeated_key_xor(plain_text, key)


    def encrypt(self, message, num_of_rounds: int, func) -> bytes:

        if len(message) < self.n_bits:
            message = message + b' ' * (self.n_bits-len(message))

        block_len = self.n_bits // 2
        blockA = Block(message[0:block_len])
        blockB = Block(message[block_len:])

        def swap(A, B):
            temp = A
            A = B
            B = temp
            return A, B

        for i in range(num_of_rounds):
            temp_bit = func(blockB.get_value())
            blockA = Block(FeistelN.repeated_key_xor(blockA.get_value(), temp_bit))

            blockA, blockB = swap(blockA, blockB)

        blockA, blockB = swap(blockA, blockB)
        return blockA.get_value() + blockB.get_value()


    def decrypt(self, message, num_of_rounds, func) -> bytes:
        # b = bytes.fromhex(message)
        return self.encrypt(message, num_of_rounds, func)


    def DE(self, message, num_of_rounds, func, mode='e', inp='l'):
        mode = mode.lower()
        inp = inp.lower()
        if inp not in ['s', 'l']: raise Exception("inp needs to be l or s!")

        def split_nth(str1, n):
            return [str1[i:i + n] for i in range(0, len(str1), n)]
        if mode == 'e':
            ra = []
            ml = split_nth(message, self.n_bits)
            for i in ml:
                ra.append(self.encrypt(i, num_of_rounds, func))
            if inp == 'l':
                return ra
            elif inp == 's':
                return b"".join(ra)
        elif mode == 'd':
            ra1 = []
            if inp == 's': message = split_nth(message, self.n_bits)
            for e in message:
                ra1.append(self.decrypt(e, num_of_rounds, func))
            return b''.join(ra1)

    @staticmethod
    def fRAB(b):
        return CHAObject.RAB(b)

    @staticmethod
    def fRAB_with_nonce(nonce, padding=None, shuffle_list=None, size=None, rep=None, char_set=None, smio=None, rev=None):
        def repeated_key_xor(plain_text, key):
            pt = plain_text
            len_key = len(key)
            encoded = []

            for i in range(0, len(pt)):
                encoded.append(pt[i] ^ key[i % len_key])
            return bytes(encoded)

        def fnonce(b):
            b = b + nonce
            chaO = CHAObject.Better_RAB_Caller(b, padding, shuffle_list, size, rep, char_set, smio, rev)
            return repeated_key_xor(chaO, nonce)
        return fnonce

    @staticmethod
    def fCHAB_with_nonce(nonce, padding, shuffle_list, slo0, rep, char_set, shift, rev):
        def repeated_key_xor(plain_text, key):
            pt = plain_text
            len_key = len(key)
            encoded = []

            for i in range(0, len(pt)):
                encoded.append(pt[i] ^ key[i % len_key])
            return bytes(encoded)

        def fnonce(b):
            b = b + nonce
            chaO = CHAObject.CHAB(b, padding, shuffle_list, slo0, rep, char_set, shift, rev)
            return repeated_key_xor(chaO, nonce)

        return fnonce


class CHAFHMAC:
    IPAD = b'\x36'
    OPAD = b'\x5c'

    def __init__(self, key: bytes, func, msg=b''):
        self.k1, self.k2 = CHAFHMAC.make_keys(key)
        self.func = func
        self.msg = msg

    @staticmethod
    def make_keys(key):
        def repeated_key_xor(plain_text, key):
            pt = plain_text
            len_key = len(key)
            encoded = []

            for i in range(0, len(pt)):
                encoded.append(pt[i] ^ key[i % len_key])
            return bytes(encoded)
        k1 = repeated_key_xor(key, CHAFHMAC.IPAD)
        k2 = repeated_key_xor(key, CHAFHMAC.OPAD)
        return k1, k2

    def update(self, message):
        self.msg += message

    def hexdigest(self, cha_hex_value=128):
        first = self.func(self.k1 + self.msg)
        second = self.func(self.k2 + first)
        r = CHAObject(int(second.hex(), 16)).hexdigest(cha_hex_value)
        return r

    def digest(self, cha_hex_value=128):
        first = self.func(self.k1 + self.msg)
        second = self.func(self.k2 + first)
        r = CHAObject(int(second.hex(), 16)).digest(cha_hex_value)
        return r

    def verify(self, mac):
        digest = list(self.hexdigest())
        r = True
        for i in range(len(digest)):
            if digest[i] != list(mac)[i % len(mac)]: r = False
        if len(digest) != len(mac): r = False
        return r



