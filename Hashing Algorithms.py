import string as st
import hashlib
import random
class HASHash:
    """
        Hashing . Algorithm. Simple
        ---------------------------
    """
    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return self.num()

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
    def CHA(message: str, padding: str, shaffle_list: list, size_limit_of_0: int, rep: int, char_set: str):
        """
        Customizable-Hashing-Algorithm
        CHA is like HAS but customizable

        :param message: The plaintext input
        :param padding: The padding as a byte string separated by a ' ', like : '01110011 00110011 11000110'
        :param shaffle_list: the letter shuffle list
        :param size_limit_of_0: how many 0 are allowed,
        :param rep: the number of repetition
        :param char_set: the charset, will be appended to the english alphabet
        :return: HASHash
        """
        common_alphabets = 'ñАБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯابجدهوزحطيكلمنسعفصقرشتثخذضظغäöüß'
        characters = st.ascii_letters + st.digits + st.punctuation + char_set + common_alphabets + ' '
        padding_list = padding.split(" ")
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
            shift_must = ord(om[0]) if len(om) > 0 else 153
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
            for i in range(amount_to_shift):
                first = padding_list.pop(0)
                padding_list.append(first)
            message = s
        last_int = int(s)
        return HASHash(last_int)

    @staticmethod
    def RandomShaffle(charset):
        letters = st.ascii_letters + st.digits + st.punctuation + ' ' + "ñАБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯابجدهوزحطيكلمنسعفصقرشتثخذضظغäöüß" + charset
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
    def HAS(message: str):
        padding = '01110011 00110011 11000110 10001101 01100111 00010001 00001110 11100100 11111100 11010111 10010111 00001111 01100111 10010100 11100101 00010100 00010110 11101011 00111110 01110000 00010000 00010100 11111110 11000101 11000011 00000100 01011011 01100010 01101000 10001001 00110000 11100000 00000100 00000010 01001111 00110011 11110101 01010101 11011111 00011010 01010101 01100110 10110110 11110110 00000000 11011111 11101100 01011100 11111110 11111011 11011100 00010001 00100100 00101100 11101100 11000111 10110111 11000100 10001010 11101111 00010010 00101011 11000111'
        shaffle_list = ['4', '?', 'З', 'A', 'Q', '~', 'Р', '$', 'U', '1', 'M', '9', '{', 'F', 'y', 'ث', 'Z', 'a', '!', 'K', 'C', 'ß', 'Ц', 'غ', 'W', 't', 'ظ', 'И', 'ط', 'z', '=', '_', '3', 'Д', 'ö', 'Ж', 'Л', 'L', 'ض', 'ش', '%', 'В', 'T', 'ص', 'Ф', 'С', 's', 'Г', 'خ', 'ل', 'D', 'f', 'ü', '}', '2', '5', '/', '6', 'ز', 'ت', 'e', '(', 'v', '\\', 'ف', '|', '^', '[', '"', 'ن', ':', 'ر', ']', 'ه', 'Ш', 'К', 'Х', '*', 'V', ' ', 'ج', 'ب', '<', "'", 'H', 'l', 'Й', 'د', 'Н', 'Б', '8', 'Ъ', '+', 'ح', 'Щ', 'ك', 'Е', 'q', ',', 'Я', 'S', 'O', 'ñ', 'g', '@', 'c', 'Ч', 'Ь', 'r', 'h', 'J', '-', 'k', 'А', 'П', 'Ю', '7', '&', 'n', 'و', 'Ы', 'ا', '.', 'ق', '>', 'B', 'У', 'س', 'u', 'X', '0', ')', 'М', 'Т', 'i', 'E', 'd', 'Ё', 'ع', 'I', 'N', 'b', 'Э', 'R', 'o', 'م', 'Y', 'ذ', 'G', ';', 'О', 'w', 'x', '#', 'ä', 'j', 'ي', 'm', 'P', 'p', '`']
        return HASHash.CHA(message, padding, shaffle_list, 155, 1000, '')

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
