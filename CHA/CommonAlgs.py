
class CommonAlgs:

    @staticmethod
    def split_nth(n: int, line: str or bytes) -> list:
        return [line[i:i + n] for i in range(0, len(line), n)]

    @staticmethod
    def repeated_key_xor(plain_text: bytes, key: bytes) -> bytes:
        pt = plain_text
        len_key = len(key)
        encoded = []

        for i in range(0, len(pt)):
            encoded.append(pt[i] ^ key[i % len_key])
        return bytes(encoded)



