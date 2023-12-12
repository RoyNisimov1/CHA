import string as st
import hashlib
import secrets
from .CommonAlgs import CommonAlgs
class CHAObject:
    @staticmethod
    def get_RA_args(f='b'):
        padding = "00001000 00110011 00110111 11100001 01011110 00000111 11010110 10001000 01101111 01001100 00010110 00010001 11100011 00010000 00011110 11101001 11001111 11010011 10111000 01001110 01011010 00101010 10000001 00101111 10011100 11000100 11011001 01100001 10111001 10101101 11011110 11000110 11001110 10101010 01110100 11111100 00100100 01011001 00010100 10001100 10001000 11100110 00001111 10010011 11001110 01111110 10011001 11001000 01101111 10000011 01101001 00110110 01001010 11010100 01110001 00101010 11010010 11111011 10011001 11010001 00001100 01110001 11011111 01010110"
        shuffle_key = ['\x0c', '«', '[', 'ل', '\x97', '=', 'Ô', "'", '\x02', 'Й', '·', '¦', '¾', '#', 'Ä', 'Ã', 'º',
                       'O', '¯', '\x92', '\x9f', '÷', 'Û', 'f', '¤', '~', 't', 'D', 'o', ',', 'ù', 'å', 'ج', 'Z', ')',
                       '\x87', '\x04', 'á', '\x96', '\x0e', 'خ', '|', 'Я', 'â', 'd', 'О', 'Л', 'Ì', 's', 'N', '³',
                       '\x11', 'X', 'ف', 'g', 'ú', 'Z', 'B', '¥', 'T', '\x85', 'Б', '\x81', 'q', ':', 'E', 'e', ')',
                       '\x83', '7', 'ö', '\x9e', 'V', 'Ó', 'ö', 'S', 'd', '9', '\x0f', 'Ý', 'Ç', 'М', 'Á', 'ø', 'z',
                       '\x94', 'ß', 'ñ', "'", 'i', '\x9d', 'ê', 'æ', 'V', 'Y', '5', 'ë', '1', '?', '\x1e', '2', '\x8b',
                       '/', 'è', '\x16', '0', 'Â', '3', ']', 'Í', '}', '\x0b', '!', '<', '\x01', 'ü', '\x01', 'w', 'Д',
                       '\x93', 'F', '8', 'س', 'Ò', 'Ё', '¡', '¹', '\x08', 'n', 'И', 'ذ', '\x17', 'ك', '?', 'К', 'Y',
                       '\x19', '%', 'ث', 'Î', '/', '@', '(', 'Ч', '<', 'ô', '{', '\r', '\x9b', '\x84', '\x0e', 'I', 'i',
                       '~', 'ì', 'a', 'ý', '3', 'P', 'Q', '*', '%', '\x07', '\x0c', 'З', 'ق', 'j', 'J', '¼', '\x1d',
                       '\\', 'ي', '\x1f', '[', '\x8c', '9', '\x8a', 'W', 'u', 'Æ', '6', 'µ', 'ã', 'د', 'b', 'Э', '_',
                       '+', 'Ï', '#', '+', 'c', 's', '\x99', '\t', '-', 'j', ':', '1', '}', '¢', 'U', 'ÿ', 'ó', '¶',
                       't', '(', 'ه', ';', 'r', 'Ø', '\x04', '±', '\xad', 'A', '\x07', '¿', 'C', 'k', 'Ф', 'í', '\x14',
                       'ñ', 'H', 'Ц', '©', '½', '\x8f', 'r', 'f', 'С', '`', 'Ü', '&', 'c', '²', '\x89', 'ش', 'þ', 'J',
                       'ز', 'n', '\x13', '\x03', '\n', '\x82', '\x18', '\x88', '8', 'ï', 'Õ', 'M', 'Ê', 'Н', 'ض', 'È',
                       'v', '^', 'v', ' ', '\t', 'l', '7', 'é', '\\', '\x05', '\x03', '2', '4', 'I', '_', '\x86', 'B',
                       'g', '´', 'k', 'w', '\x1b', 'ا', '"', 'E', '\x05', 'H', 'Т', 'ظ', '^', 'x', '.', '\x1c', '\x0f',
                       '»', 'ر', '§', 'ß', 'G', 'ع', 'û', '\x06', 'z', '6', '{', 'y', '5', '\x7f', '®', 'C', 'Щ', '4',
                       '\x8d', 'Р', 'X', 'ü', 'h', 'U', '\x02', '*', 'Þ', 'Ù', '\r', '¨', 'Å', '.', ',', 'm', 'Ú', 'F',
                       'q', '\x06', 'ط', 'غ', 'و', '"', 'Ю', 'y', 'ª', '\x0b', 'T', 'ن', 'G', 'õ', '&', '-', 'K', 'Ж',
                       'А', 'e', 'ä', '\x91', 'Ñ', '\x00', 'R', '\x9c', '$', 'M', 'L', 'S', 'É', 'x', '\x98', 'Ш', 'D',
                       'ب', 'Q', 'Ë', 'L', 'П', 'Г', 'ص', '>', '\x8e', 'K', '\x15', 'ç', 'a', '\n', 'u', '×', '\x08',
                       '|', '\x1a', '>', 'ت', 'm', 'ò', 'h', 'ä', 'م', '£', '\x95', 'l', '¬', 'Х', 'Ы', 'p', 'î', 'N',
                       'O', ']', '=', 'Ъ', 'В', '\x12', '\x9a', ';', 'b', 'o', 'A', '!', 'У', '$', 'Ö', 'ح', 'R', 'Ь',
                       'Е', 'W', '¸']

        size = 155
        rep = 16
        char_set = ''
        smio = 153
        rev = 4
        if f == 'n': padding = '8 51 55 225 94 7 214 136 111 76 22 17 227 16 30 233 207 211 184 78 90 42 129 47 156 196 217 97 185 173 222 198 206 170 116 252 36 89 20 140 136 230 15 147 206 126 153 200 111 131 105 54 74 212 113 42 210 251 153 209 12 113 223 86'
        return padding, shuffle_key, size, rep, char_set, smio, rev

    def __init__(self, value: int):
        self.value = value

    def __repr__(self):
        return str(self.hexdigest())

    def hexdigest(self, b=None):
        if b is None:
            d = self.digest(128)
            return d.hex()
        return self.digest(b).hex()


    def digest(self, num_bits=128):
        r = int(self.value).to_bytes(int(self.value).bit_length(), 'little').rstrip(b'\x00')[0:num_bits // 2]
        return r

    def num(self):
        return self.value


    @staticmethod
    def CHA(message: str, padding: str, shuffle_list: list, size_limit_of_0: int, rep: int, char_set: str, shift_must_if_om0: int, rev_every: int, padding_in='b'):
        """
        Customizable-Hashing-Algorithm

        :param padding_in: how does the pudding list gets interpreted
        :param rev_every: reverse the lists every
        :param shift_must_if_om0: what's shift must is
        :param message: The plaintext input
        :param padding: The padding as a byte string separated by a ' ', like : '01110011 00110011 11000110'
        :param shuffle_list: the letter shuffle list
        :param size_limit_of_0: how many 0 are allowed,
        :param rep: the number of repetition
        :param char_set: the charset, will be appended to the english alphabet
        :return: CHAObject
        """
        shuffle_list = shuffle_list.copy()
        common_alphabets = 'ñАБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯابجدهوزحطيكلمنسعفصقرشتثخذضظغäöüß'
        characters = st.ascii_letters + st.digits + st.punctuation + char_set + common_alphabets + ' ' + "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x01\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x02\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x03\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x04\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x05\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x06\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x07\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x08\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x09\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\x0a\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\x0b\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\x0c\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\x0d\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\x0e\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\x0f\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
        padding_list = padding.split(" ")
        if len(padding_list) == 0: raise ValueError("Padding can not be empty!")
        if padding_in == 'n':
            new_list = []
            for i in padding_list:
                new_list.append(format(int(i), 'b'))
            padding_list = new_list.copy()
        elif padding_in == 'h':
            new_list = []
            for i in padding_list:
                new_list.append(format(int(i, 16), 'b'))
            padding_list = new_list.copy()


        def shuffle(to_shuffle_list: list, n=2):
            to_shuffle_list = to_shuffle_list.copy()
            to_append_size = to_shuffle_list[0]
            a = []
            for i1 in range(to_append_size % len(to_shuffle_list)):
                a.append(to_shuffle_list.pop(0))
            to_shuffle_list.reverse()
            for i2 in a:
                to_shuffle_list.append(i2)
            e = []
            for i3, ch in enumerate(to_shuffle_list):
                if i3 % (n+1) == 0:
                    e.append(to_shuffle_list.pop(i3))
            for i4 in e:
                to_shuffle_list.append(i4)
            return to_shuffle_list
        s = ''
        # rep is the number of times this happens
        for times in range(rep):
            original_message = []
            # enciphers
            for c in message:
                for i in range(0, pow(ord(c), ord(c), len(shuffle_list))):
                    first = shuffle_list.pop(0)
                    shuffle_list.append(first)
                ord_shuffle_list = [ord(c) for c in shuffle_list]
                shuffled = shuffle(ord_shuffle_list, ord(c) % 10)
                shuffle_list = [chr(c) for c in shuffled]
                if c in characters and c in shuffle_list:
                    index = characters.index(c)
                    original_message.append(shuffle_list[index])
                else:
                    original_message.append(c)
            # pads
            binary_formatted_message = [format(ord(c), 'b') for c in original_message]

            amount_to_shift = len(padding_list) - len(binary_formatted_message)
            if amount_to_shift <= 0: amount_to_shift *= -1
            shift_must = ord(original_message[0]) if len(original_message) > 0 else shift_must_if_om0
            amount_to_shift += shift_must
            binary_formatted_message.extend(padding_list)

            # keys and shuffles
            key = binary_formatted_message.copy()
            for i in range(0, amount_to_shift):
                if times % rev_every == 0:
                    key.reverse()
                first = key.pop(0)
                key.append(first)
            if key == binary_formatted_message:
                first = key.pop(0)
                key.append(first)
            # xors
            binary_formatted_message = list(int(c, 2) for c in binary_formatted_message)
            key = list(int(c, 2) for c in key)
            xored = []
            for i in range(len(binary_formatted_message)):
                xored.append(binary_formatted_message[i] ^ key[i])
            # final
            s_xored = [str(n) for n in xored]
            s = ''
            for string in s_xored:
                s += string.strip("-")
            s = s[0:size_limit_of_0]
            for i in range(pow(amount_to_shift, amount_to_shift, len(padding_list))):
                intL = [int(c, 2) for c in padding_list]
                padding_list = shuffle(intL, i%10)
                padding_list = [format(c, 'b') for c in padding_list]
            message = s
        last_int = int(s)
        return CHAObject(last_int)

    @staticmethod
    def CHAB(message: bytes, padding: str, shuffle_list: list, size_limit_of_0: int, rep: int, char_set: str,
             shift_must_if_om0: int, rev: int):
        mess = str(message)
        c = CHAObject.CHA(mess, padding, shuffle_list, size_limit_of_0, rep, char_set, shift_must_if_om0, rev)
        return c.digest()


    @staticmethod
    def RA(message: str):
        padding, shuffle_list, size, rep, char_set, smio, rev = CHAObject.get_RA_args('n')
        return CHAObject.CHA(message, padding, shuffle_list, size, rep, char_set, smio, rev, padding_in='n')

    @staticmethod
    def RAB(message: bytes):
        padding, shuffle_list, size, rep, char_set, smio, rev = CHAObject.get_RA_args()
        return CHAObject.CHAB(message, padding, shuffle_list, size, rep, char_set, smio, rev)

    @staticmethod
    def Better_RAB_Caller(message: bytes, padding=None, shuffle_list=None, size=None, rep=None, char_set=None, smio=None, rev=None):
        padding1, shuffle_list1, size1, rep1, char_set1, smio1, rev1 = CHAObject.get_RA_args()
        if padding: padding1 = padding
        if shuffle_list: shuffle_list1 = shuffle_list
        if size: size1 = size
        if rep: rep1 = rep
        if char_set: char_set1 = char_set
        if smio: smio1 = smio
        if rev: rev1 = rev
        return CHAObject.CHAB(message, padding1, shuffle_list1, size1, rep1, char_set1, smio1, rev1)

class HashMaker:
    @staticmethod
    def RandomShaffle(charset):
        letters = st.ascii_letters + st.digits + st.punctuation + ' ' + "ñАБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯابجدهوزحطيكلمنسعفصقرشتثخذضظغäöüß" + charset + "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x01\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x02\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x03\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x04\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x05\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x06\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x07\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x08\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x09\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\x0a\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\x0b\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\x0c\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\x0d\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\x0e\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\x0f\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
        letters = list(letters)
        secrets.SystemRandom().shuffle(letters)
        return letters

    @staticmethod
    def RandomBits(how_many: int, group=8, how_to_format=' '):
        bit_list = []
        for i in range(how_many):
            to_append = ''
            for j in range(group):
                to_append += str(secrets.choice([0, 1]))
            bit_list.append(to_append)
        if how_to_format == ' ':
            return ' '.join(bit_list)
        elif how_to_format == 'l':
            return bit_list.copy()
        else:
            raise Exception("How to format can be ' ' or 'l'!")

    @staticmethod
    def get_CHA_args():
        padding = HashMaker.RandomBits(64)
        shuffle_key = HashMaker.RandomShaffle("")
        return padding, shuffle_key
class Krhash:


    @staticmethod
    def repeated_key_xor(plain_text, key):
        return CommonAlgs.repeated_key_xor(plain_text, key)

    @staticmethod
    def Krhash(m: bytes) -> bytes:
        to_do = CommonAlgs.split_nth(64, m)
        to_do = [to_do[i] + bytes((i % 256)) for i in range(len(to_do))]
        new_to_do = []
        for i in range(len(to_do)):
            to_append = to_do[i]
            if i % 2:
                l = list(to_append)
                l.reverse()
                to_append = bytes(l)
            if i % 3:
                l = list(to_append)
                for j in range(l[0] % len(l)):
                    l.append(l.pop(0))
                to_append = bytes(l)

            new_to_do.append(to_append)
        to_do = new_to_do
        to_xor = []
        def shuffle(l: list) -> list:
            l = l.copy()
            for i in range(len(l)):
                l[i] = (l[i] >> 2) * 7 & 9
                if l[i] % (l[i] % 10 + 1) == 0:
                    l[i] |= 5
                else:
                    l[i] |= l[i] & 21
                l[i] %= 256
            cut = len(l) // 2
            a1 = l[:cut]
            a2 = l[cut:]
            a1.reverse()
            a2.reverse()
            a1.extend(a2)
            out = [a ^ b for a in a1 for b in a1]
            for i in range(len(l)):
                if i % ((out[i] % 10) + 1) == 0:
                    out[i] = ((out[i] << 17) | 7) & 21
                out[i] |= l[i]
                out[i] %= 256
            return out

        def shuffle1(to_shuffle_list: list, n=2):
            def func(to_shuffle_list, n=2):
                to_shuffle_list = to_shuffle_list.copy()
                to_append_size = to_shuffle_list[0]
                a = []
                for i1 in range(to_append_size % len(to_shuffle_list)):
                    a.append(to_shuffle_list.pop(0))
                to_shuffle_list.reverse()
                for i2 in a:
                    to_shuffle_list.append(i2)
                e = []
                for i3, ch in enumerate(to_shuffle_list):
                    if i3 % (n+1) == 0:
                        e.append(to_shuffle_list.pop(i3))
                for i4 in e:
                    to_shuffle_list.append(i4)
                return to_shuffle_list
            f = func(to_shuffle_list, 3)
            l = [i % 256 for i in f]
            return bytes(l)
        for m in to_do:
            for i in range(1):
                m = m + b"\xff"
                p = Krhash.repeated_key_xor(m, b"\xee\xff" + m)
                for i in range(4):
                    p = Krhash.repeated_key_xor(m, bytes(len(m)) + bytes(p))
                m += bytes(p)
                l = list(m)
                for i in range(m[0] % len(l)):
                    l.append(l.pop(0))
                m = bytes(l)
                out = shuffle(list(m))
                rev = out.copy()
                rev.reverse()
                first_xor = Krhash.repeated_key_xor(out, rev)
                rev_m = list(m)
                rev_m.reverse()
                rev_m = shuffle(rev_m)
                second_xor = Krhash.repeated_key_xor(m, rev_m)
                m = Krhash.repeated_key_xor(first_xor, second_xor)[:64]
                m = shuffle1(list(m))
                s1 = shuffle1(list(m)[:8])[:16]
                s2 = shuffle1(list(m)[:16])[:8]
                s1int = list(s1)
                s2int = list(s2)
                for i in range(len(s1)):
                    if i % ((s1int[i] % 10) + 1) == 0:
                        s1int[i] = ((s1int[i] << 17) | 7) & 21
                    s1int[i] |= 2
                    s1int[i] %= 256
                s1 = b"".join([chr(c).encode() for c in s1int])
                s2 = b"".join([chr(c).encode() for c in s2int])
                m = Krhash.repeated_key_xor((s2 + s1 + m)[:64], s1 + s2 + m[:4])[:64]
                l = list(m)
                for i in range(m[0] % len(l)):
                    first = l.pop(0)
                    if len(l) > 1:
                        first = first ^ l[1]
                    first = first ^ 5 | 23 & 3
                    first %= 256
                    l.append(first)
                m = bytes(l)

            s1 = shuffle1(list(m)[:21])[:16]
            s2 = shuffle1(list(m)[:16])[:8]
            s1int = list(s1)
            s2int = list(s2)
            for i in range(len(s1)):
                if i % ((s1int[i] % 10) + 1) == 0:
                    s1int[i] = ((s1int[i] << 17) | 7) & 21
                    s1int.append((s2int.pop(0) | 278) % 256)
                    s2int.append((s1int.pop(0) & 6) % 256)
                s1int[i] |= 2
                s1int[i] %= 256
                s1int.append((s2int.pop(0) | 5) % 256)
                s2int.append((s1int.pop(0) & 2111) % 256)
            s1 = bytes(s1int)
            s2 = bytes(s2int)
            l = list(s2 + m + s1)
            for i in range(m[0] % len(l)):
                first = l.pop(0)
                if (i + s2[i % len(s2)]) % 3 == 0:
                    first = first ^ l[i % len(l)]
                first = first ^ s1[i % len(s1)] * 23 // 51
                first %= 256
                l.append(first)
                l = list(shuffle1(l, i + 6))
            m = shuffle1(l, 2)
            m = Krhash.repeated_key_xor((s2 + s1 + m)[:64], s1 + s2 + m[:4])[:64]
            out = Krhash.repeated_key_xor((s2 + m + s1 + m)[:64], m + Krhash.repeated_key_xor(s2, s1) + s1)[:64]
            to_xor.append(out)
        out = to_xor[0]
        for i in range(1, len(to_xor)):
            out = Krhash.repeated_key_xor(out, to_xor[i])

        return out

if __name__ == '__main__':
    while True:
        m = input("Message\n")
        n_bits = input('You can put the length that you want in hexdigest(n_bits), for 512 put 128, 1/4:\n')
        if n_bits.isspace() or n_bits == '': n_bits = 128
        n_bits = int(n_bits)
        h = CHAObject.RA(m)
        h2 = hashlib.sha512(m.encode())
        print('Hex:')
        print(f"RA Hex:\n{h.hexdigest(n_bits)}")
        print(f"Sha512 Hex:\n{h2.hexdigest()}")
        print('\nDigest:')
        print(f"RA Digest:\n{h.digest(n_bits)}")
        print(f"Sha512 Digest:\n{h2.digest()}")
        print('\nNums:')
        print(f"RA Num:\n{h.num()}")
        print(f"Sha512 Num:\n{int(h2.hexdigest(),16)}")
