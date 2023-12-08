class PKCS7(object):
    def __init__(self, block_size):
        self.block_size = block_size

    def pad(self, byte_str: bytes) -> bytes:
        padding_number = self.block_size - len(byte_str) % self.block_size
        if padding_number == self.block_size:
            return byte_str
        padding = chr(padding_number).encode() * padding_number
        return byte_str + padding

    def unpad(self, byte_str: bytes) -> bytes:
        if not byte_str: return byte_str
        if len(byte_str) % self.block_size:
            return byte_str
        padding_number = byte_str[-1]
        if padding_number >= self.block_size:
            return byte_str
        else:
            if all(padding_number == c for c in byte_str[-padding_number:]):
                return byte_str[0:-padding_number]
            else:
                return byte_str
