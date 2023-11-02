import json

from Hashing_Algorithms import *
import ast
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
            return A, B

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
    def DE(message, num_of_rounds, func, mode='e', inp='l'):
        mode = mode.lower()
        inp = inp.lower()
        if inp not in ['s', 'l']: raise Exception("inp needs to be l or s!")

        def split_nth(str1, n):
            return [str1[i:i + n] for i in range(0, len(str1), n)]
        if mode == 'e':
            ra = []
            ml = split_nth(message, 64)
            for i in ml:
                ra.append(Feistel64.encrypt(i, num_of_rounds, func).hex())
            if inp == 'l':
                return ra
            elif inp == 's':
                return "".join(ra)
        elif mode == 'd':
            ra1 = []
            if inp == 's': message = split_nth(message, 128)
            for e in message:
                ra1.append(Feistel64.decrypt(e, num_of_rounds, func))
            return b''.join(ra1)

if __name__ == '__main__':
    with open("Key.json", "r") as f:
        data = json.loads(f.read())
    key_name = input('Key name:\n')
    if key_name not in data:
        data[key_name] = {"padding": "", "shuffle": []}
    if data[key_name]["padding"] == '':
        print("No key is set up!")
    mode = input("""1) Showcase
2) Encrypt
3) Decrypt
4) Exit
5) Generate
6) Get Showcase args
7) Set Key
8) Get current key
9) Delete key
""")

    def get_args():
        return data[key_name]['padding'], data[key_name]['shuffle'].copy(), data[key_name]['slo0'], data[key_name]['rep'], data[key_name]['charset'], data[key_name]['shift']

    def fCHA(b):
        padding, shuffle_list, slo0, rep, char_set, shift = get_args()
        return CHAObject.CHAB(b, padding, shuffle_list, slo0, rep, char_set, shift)
    if mode == '1':
        padding, shuffle_list, slo0, rep, char_set, shift = get_args()
        s = input("Enter an input:\n").encode()
        inp = input('Provide and inp:\n')
        e = Feistel64.DE(s,  rep, fCHA, "e", inp)
        print(e)
        d = Feistel64.DE(e,  rep, fCHA, 'd', inp)
        print(d.decode().strip())
    elif mode == '2':
        padding, shuffle_list, slo0, rep, char_set, shift = get_args()
        s = input("Enter an input:\n").encode()
        inp = input('Provide and inp:\n')
        e = Feistel64.DE(s, rep, fCHA, "e", inp)
        print(e)
    elif mode == '3':

        padding, shuffle_list, slo0, rep, char_set, shift = get_args()
        s = input("Enter an input:\n")
        inp = input('Provide and inp:\n')
        if len(inp) == 0: inp = 'l'
        d = Feistel64.DE(s, rep, fCHA, "d", inp)
        print(d.decode().strip())
    elif mode == '4': exit()
    elif mode == '5': HashMaker.get_CHA_args()
    elif mode == '6':
        padding, shuffle_list, size, rep, char_set, smio = CHAObject.get_RA_args()
        print(padding, shuffle_list, size, rep, char_set, smio, sep='\n')
    elif mode == '7':
        p = input("padding\n")
        s = ast.literal_eval(input('shuffle:\n'))
        slo0 = int(input("slo0\n"))
        rep = int(input("rep\n"))
        charset = input("chrset\n")
        shift_must = int(input("shift must\n"))
        data[key_name]['padding'] = p
        data[key_name]["shuffle"] = s
        data[key_name]["slo0"] = slo0
        data[key_name]["rep"] = rep
        data[key_name]["charset"] = charset
        data[key_name]["shift"] = shift_must
        with open("Key.json", "w") as f:
            f.write(json.dumps(data, indent=2))
    elif mode == '8':
        print(f"Padding:\n{data[key_name]['padding']}\nShuffle list:\n{data[key_name]['shuffle']}")

    elif mode == '9':
        yes_or_no = input("Are your sure? this action can not be undone!").lower()
        if yes_or_no in ['y', 'yes']:
            if input("type 'Delete'").lower() == 'delete':
                del data[key_name]

    with open("Key.json", "w") as f:
        f.write(json.dumps(data, indent=2))
