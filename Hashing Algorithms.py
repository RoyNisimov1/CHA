import string as st
import hashlib
import random
class HASHash:
    """
        Hashing . Algorithm. Simple
        ---------------------------
    """
    @staticmethod
    def get_HAS_args():
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

        size = 154
        rep = 500
        char_set = ''
        smio = 153
        return padding, shuffle_key, size,rep,char_set,smio

    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return str(self.hexdigest())

    def hexdigest(self, b=None):
        if b is None:
            return hex(self.value).strip("0x")
        return hex(self.value).strip("0x")[0:b]


    def digest(self, num_bits=128):
        r = int(self.value).to_bytes(int(self.value).bit_length(), 'little').rstrip(b'\x00')[0:num_bits // 2]
        return r

    def num(self):
        return self.value

    @staticmethod
    def HASS(message: str, size_limit_of_0=155):
        """
        :param message: the message
        :param size_limit_of_0: how many 0 are allowed,
        :return: HASHash
        """
        chars = st.ascii_letters + st.digits + st.punctuation + ' '
        shuffled = ['9', 'n', '5', '<', '0', 'W', '_', '\\', '2', 'e', '(', 'u', "'", 'f', '~', 'y', 'v', 'U', 'O', 'N', 'm', 'F', '[', '+', 'i', 'Y', 'T', ':', 'B', 'Q', 'R', 'I', 'z', '?', 'L', 'j', '1', '*', ' ', 'J', 'q', 'r', 'X', '%', 'Z', '{', '7', 'h', 's', ';', '-', '!', 'b', 'M', 'k', 'c', '|', 'd', '&', 'V', 'l', 'P', '"', 'C', '@', 'H', 'a', '4', 'w', '=', 'x', '.', ',', '8', '6', 'G', 'g', 'A', '`', 't', ')', '#', '^', '/', '3', 'E', '$', '}', 'o', 'p', '>', 'D', 'S', 'K', ']']
        return_str = ''
        for ch in message:
            for i in range(0, ord(ch)):
                first = shuffled.pop(0)
                shuffled.append(first)
            if ch not in shuffled or ch not in chars: continue
            index = chars.index(ch)
            return_str += shuffled[index]
        s = ''
        for c in return_str:
            s += str(ord(c)**ord(c))
            if len(s) >= size_limit_of_0:
                break
        s = s[0:size_limit_of_0]
        if len(s) > 0:
            last = int(s)
        else:
            last = 1
        return HASHash(last)

    @staticmethod
    def CHA(message: str, padding: str, shaffle_list: list, size_limit_of_0: int, rep: int, char_set: str, shift_must_if_om0: int):
        """
        Customizable-Hashing-Algorithm
        CHA is like HAS but customizable

        :param shift_must_if_om0: what's shift must is
        :param message: The plaintext input
        :param padding: The padding as a byte string separated by a ' ', like : '01110011 00110011 11000110'
        :param shaffle_list: the letter shuffle list
        :param size_limit_of_0: how many 0 are allowed,
        :param rep: the number of repetition
        :param char_set: the charset, will be appended to the english alphabet
        :return: HASHash
        """
        common_alphabets = 'ñАБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯابجدهوزحطيكلمنسعفصقرشتثخذضظغäöüß'
        characters = st.ascii_letters + st.digits + st.punctuation + char_set + common_alphabets + ' ' + "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x01\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x02\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x03\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x04\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x05\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x06\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x07\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x08\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x09\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\x0a\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\x0b\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\x0c\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\x0d\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\x0e\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\x0f\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
        padding_list = padding.split(" ")
        s = ''
        for times in range(rep):
            om = []

            for c in message:
                for i in range(0, pow(ord(c), ord(c), len(shaffle_list))):
                    first = shaffle_list.pop(0)
                    shaffle_list.append(first)
                if c in characters:
                    index = characters.index(c)
                    om.append(shaffle_list[index])
                else:
                    om.append(c)
            bm = [format(ord(c), 'b') for c in om]
            amount_to_shift = len(padding_list) - len(bm)
            if amount_to_shift <= 0: amount_to_shift *= -1
            shift_must = ord(om[0]) if len(om) > 0 else shift_must_if_om0
            amount_to_shift += shift_must
            for i, b in enumerate(padding_list):
                bm.append(b)
            key = bm.copy()
            for i in range(0, amount_to_shift):
                first = key.pop(0)
                key.append(first)
            if key == bm:
                first = key.pop(0)
                key.append(first)
            bm = list(int(c, 2) for c in bm)
            key = list(int(c, 2) for c in key)
            xored = []
            for i in range(len(bm)):
                xored.append(bm[i] ^ key[i])
            s_xored = [str(n) for n in xored]
            s = ''
            for string in s_xored:
                s += string.strip("-")
            s = s[0:size_limit_of_0]
            for i in range(pow(amount_to_shift, amount_to_shift, len(padding_list))):
                first = padding_list.pop(0)
                padding_list.append(first)
            message = s
        last_int = int(s)
        return HASHash(last_int)

    @staticmethod
    def CHAB(message: bytes, padding: str, shaffle_list: list, size_limit_of_0: int, rep: int, char_set: str, shift_must_if_om0: int):
        mess = str(message)
        return HASHash.CHA(mess, padding, shaffle_list, size_limit_of_0, rep, char_set, shift_must_if_om0)

    @staticmethod
    def HAS(message: str):
        padding, shuffle_list, size, rep, char_set,smio = HASHash.get_HAS_args()
        return HASHash.CHA(message, padding, shuffle_list, size, rep, char_set, smio)

    @staticmethod
    def HASB(message: bytes):
        padding, shuffle_list, size, rep, char_set,smio = HASHash.get_HAS_args()
        return HASHash.CHAB(message, padding, shuffle_list, size, rep, char_set, smio)

class HashMaker:
    @staticmethod
    def RandomShaffle(charset):
        letters = st.ascii_letters + st.digits + st.punctuation + ' ' + "ñАБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯابجدهوزحطيكلمنسعفصقرشتثخذضظغäöüß" + charset + "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x01\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x02\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x03\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x04\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x05\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x06\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x07\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x08\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x09\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\x0a\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\x0b\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\x0c\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\x0d\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\x0e\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\x0f\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
        letters = list(letters)
        random.shuffle(letters)
        return letters

    @staticmethod
    def RandomBits(how_many: int, group=8, how_to_format=' '):
        bit_list = []
        for i in range(how_many):
            to_append = ''
            for j in range(group):
                to_append += str(random.randint(0, 1))
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
        print(f"""The needed syntax is this: 
padding = "{padding}"
shuffle_key = {shuffle_key}
HASHash.CHA($INSERT MESSAGE HERE, padding, shuffle_key, 128, $REP NUM HERE (500+ for more security), '')
""")
        return padding, shuffle_key

if __name__ == '__main__':
    while True:
        m = input("Message\n")
        n_bits = input('You can put the length that you want in hexdigest(n_bits), for 512 put 128, 1/4:\n')
        if n_bits.isspace() or n_bits == '': n_bits = 128
        n_bits = int(n_bits)
        h = HASHash.HAS(m)
        h1 = HASHash.HASS(m)
        h2 = hashlib.sha512(m.encode())
        print('Hex:')
        print(f"HAS Hex:\n{h.hexdigest(n_bits)}")
        print(f"HASS Hex:\n{h1.hexdigest(n_bits)}")
        print(f"Sha512 Hex:\n{h2.hexdigest()}")
        print('\nDigest:')
        print(f"HAS Digest:\n{h.digest(n_bits)}")
        print(f"HASS Digest:\n{h1.digest(n_bits)}")
        print(f"Sha512 Digest:\n{h2.digest()}")
        print('\nNums:')
        print(f"HAS Num:\n{h.num()}")
        print(f"HASS Num:\n{h1.num()}")
        print(f"Sha512 Num:\n{int(h2.hexdigest(),16)}")
