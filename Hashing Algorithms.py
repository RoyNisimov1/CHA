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
        padding = "10110101 11101100 10011101 11111011 11000001 01011001 10111010 00010011 01001011 01100011 01010111 01010011 10100101 00111011 01011101 00111001 10001111 00000101 00101010 10101111 00100001 01111001 01010000 10011010 01010111 10101011 01101111 11110101 01101010 00101110 10110000 10000001 10100000 01001110 11111000 10101110 00110011 11101010 00001000 10010110 00111010 00011111 01010001 11101011 11001110 10011101 00110010 10011010 11000011 10101101 10101011 01111001 10011111 01000100 01111100 10101011 11011111 00111100 10101010 00101001 00000111 01101011 00000100 10111010"
        shuffle_list = ['ف', 'D', 'X', 'f', '\x18', '@', 'ظ', 'b', 'ط', 'F', 'ß', '5', 'Q', 'd', '\x97', 'د', ' ', '8',
                        'Е', 'З', 's', '6', 'ش', '4', 'ق', 'О', '`', 'ح', 'Э', '\x80', 'E', 'S', 'D', 'z', 'X', '#',
                        'O',
                        ')', 'Ц', '(', '\x19', 'ص', 'У', '8', 'Л', 'Y', '~', 'b', '!', 'Ы', 'ز', 'E', '\x98', '0',
                        '\x10', 'v', 'g', '$', '<', 'ع', 'س', 'y', '\x99', 'y', 'Ь', '\x16', 'ج', 'p', '(', 'C', 'c',
                        'P', 'u', '\x83', 'Ш', 'j', '\x82', 'Y', 'h', '\x86', '*', 'غ', 'ä', 'G', '\x13', '\x81', 'U',
                        '&', '7', 'R', 'i', 'V', '9', '_', 'i', 'ر', 'u', '`', 'Ч', 'G', "'", 'Г', 'و', '5', 'W', 'l',
                        '&', 'k', '\x00', 'F', 'H', 'Х', 'ö', '\t', '\x02', '2', 'Q', 'f', '^', ' ', 'Ж', 'Я', 't', 'Z',
                        'W', 'ذ', '[', '1', '\x08', 'م', '\x06', 'ي', 'q', '\x84', '/', '%', 'П', 'e', 'A', '\x15',
                        '\x93', 'ك', 'T', '\x95', 'Й', 'С', 'P', 'Ъ', 'g', 'H', ':', '>', 'A', 'М', '\x88', 'Ю', 'I',
                        '\x04', 'Щ', '\x90', 'S', 'ñ', 'И', 'n', '\x85', 'Б', 'o', '\\', 'Д', 'ل', '3', '\x03', ']',
                        '1',
                        '2', 'Т', 'ض', 's', 'ث', 'J', 'M', '\x12', '0', 'C', 'x', '\x11', 'v', '\x96', '{', 'I', '\x87',
                        '\x94', 'B', '"', '7', 'U', 'Н', '6', '\x07', 'B', '\x89', '4', 'r', ';', 'К', '#', 'c', "'",
                        'm', 'ü', 't', 'Ф', 'ه', '\x17', 'x', '$', 'ا', 'ت', 'w', 'q', '\x91', 'ب', '%', 'e', 'K', '+',
                        'd', 'w', 'a', 'N', '?', '"', ')', '\x01', '\x14', '3', '!', 'V', 'ن', '\x92', 'В', 'p', 'T',
                        '|', '=', '}', 'Ё', '.', 'R', '@', 'А', 'Р', 'a', '9', 'خ', 'h', ',', '\x05', 'r', '-', 'L']
        size = 154
        rep = 1000
        char_set = ''
        smio = 153
        return padding, shuffle_list, size,rep,char_set,smio

    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return self.hexdigest()

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
        characters = st.ascii_letters + st.digits + st.punctuation + char_set + common_alphabets + ' ' + "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99"
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
        letters = st.ascii_letters + st.digits + st.punctuation + ' ' + "ñАБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯابجدهوزحطيكلمنسعفصقرشتثخذضظغäöüß" + charset + "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99"
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
