import hashlib
import string as st
from Hashing_Algorithms import *

class Block:
    def __init__(self, value: str):
        self.value = value

    def get_value(self):
        return self.value

class Feistel64:

    @staticmethod
    def repeated_key_xor(plain_text, key):

        pt = plain_text
        len_key = len(key)
        encoded = []

        for i in range(0, len(pt)):
            encoded.append(pt[i] ^ key[i % len_key])
        return bytes(encoded)

    @staticmethod
    def encrypt(message, num_of_rounds: int, func) -> bytes:

        if len(message) < 64:
            message = message + b' ' * (64-len(message))

        block_len = 32
        blockA = Block(message[0:block_len])
        blockB = Block(message[block_len:])
        def swap(A, B):
            temp = A
            A = B
            B = temp
            return A,B

        for i in range(num_of_rounds):
            temp_bit = func(blockB.get_value())
            blockA = Block(Feistel64.repeated_key_xor(blockA.get_value(), temp_bit))

            blockA, blockB = swap(blockA, blockB)

        blockA, blockB = swap(blockA, blockB)
        return blockA.get_value() + blockB.get_value()

    @staticmethod
    def decrypt(message, num_of_rounds, func) -> bytes:
        b = bytes.fromhex(message)
        return Feistel64.encrypt(b, num_of_rounds, func)

    @staticmethod
    def DE(message, num_of_rounds, func, mode='e'):
        mode = mode.lower()
        def split_nth(str1, n):
            return [str1[i:i + n] for i in range(0, len(str1), n)]
        if mode == 'e':
            ra = []
            ml =split_nth(message,64)
            for i in ml:
                ra.append(Feistel64.encrypt(i, num_of_rounds, func).hex())
            return ra
        elif mode == 'd':
            ra1 = []
            for e in message:
                ra1.append(Feistel64.decrypt(e, num_of_rounds, func))
            return b''.join(ra1)
def fSha(b):
    return hashlib.sha512(b).digest()

def fCHA(b):
    padding, shuffle_list, size, rep, char_set, smio = HASHash.get_HAS_args()
    return HASHash.CHAB(b,padding,shuffle_list, 128, 16, '', 153)

e = Feistel64.DE(b"Test",  8, fCHA)
print(e)
d = Feistel64.DE(e,  8,fCHA, 'd')
print(d)
