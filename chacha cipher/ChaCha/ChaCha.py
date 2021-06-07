"""Pure Python implementation of ChaCha cipher

Implementation that follows RFC 7539 closely.
"""

from __future__ import division
from .compat import compat26Str
import copy
import os
import struct
try:
    # in Python 3 the native zip returns iterator
    from itertools import izip
except ImportError:
    izip = zip

class ChaCha(object):

    """Pure python implementation of ChaCha cipher"""

    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]

    @staticmethod
    def rotl32(v, c):
        """Rotate left a 32 bit integer v by c bits"""
        return ((v << c) & 0xffffffff) | (v >> (32 - c))

    @staticmethod
    def quarter_round(x, a, b, c, d):
        """Perform a ChaCha quarter round"""
        xa = x[a]
        xb = x[b]
        xc = x[c]
        xd = x[d]

        xa = (xa + xb) & 0xffffffff
        xd = xd ^ xa
        xd = ((xd << 16) & 0xffffffff | (xd >> 16))

        xc = (xc + xd) & 0xffffffff
        xb = xb ^ xc
        xb = ((xb << 12) & 0xffffffff | (xb >> 20))

        xa = (xa + xb) & 0xffffffff
        xd = xd ^ xa
        xd = ((xd << 8) & 0xffffffff | (xd >> 24))

        xc = (xc + xd) & 0xffffffff
        xb = xb ^ xc
        xb = ((xb << 7) & 0xffffffff | (xb >> 25))

        x[a] = xa
        x[b] = xb
        x[c] = xc
        x[d] = xd

    _round_mixup_box = [(0, 4, 8, 12),
                        (1, 5, 9, 13),
                        (2, 6, 10, 14),
                        (3, 7, 11, 15),
                        (0, 5, 10, 15),
                        (1, 6, 11, 12),
                        (2, 7, 8, 13),
                        (3, 4, 9, 14)]

    @classmethod
    def double_round(cls, x):
        """Perform two rounds of ChaCha cipher"""
        for a, b, c, d in cls._round_mixup_box:
            xa = x[a]
            xb = x[b]
            xc = x[c]
            xd = x[d]

            xa = (xa + xb) & 0xffffffff
            xd = xd ^ xa
            xd = ((xd << 16) & 0xffffffff | (xd >> 16))

            xc = (xc + xd) & 0xffffffff
            xb = xb ^ xc
            xb = ((xb << 12) & 0xffffffff | (xb >> 20))

            xa = (xa + xb) & 0xffffffff
            xd = xd ^ xa
            xd = ((xd << 8) & 0xffffffff | (xd >> 24))

            xc = (xc + xd) & 0xffffffff
            xb = xb ^ xc
            xb = ((xb << 7) & 0xffffffff | (xb >> 25))

            x[a] = xa
            x[b] = xb
            x[c] = xc
            x[d] = xd

    @staticmethod
    def chacha_block(key, counter, nonce, rounds):
        """Generate a state of a single block"""
        state = ChaCha.constants + key + [counter] + nonce

        working_state = state[:]
        dbl_round = ChaCha.double_round
        for _ in range(0, rounds // 2):
            dbl_round(working_state)

        return [(st + wrkSt) & 0xffffffff for st, wrkSt
                in izip(state, working_state)]

    @staticmethod
    def word_to_bytearray(state):
        """Convert state to little endian bytestream"""
        return bytearray(struct.pack('<LLLLLLLLLLLLLLLL', *state))

    @staticmethod
    def _bytearray_to_words(data):
        """Convert a bytearray to array of word sized ints"""
        ret = []
        for i in range(0, len(data)//4):
            ret.extend(struct.unpack('<L',
                                     compat26Str(data[i*4:(i+1)*4])))
        return ret

    def __init__(self, key, nonce, counter=0, rounds=20):
        """Set the initial state for the ChaCha cipher"""
        if len(key) != 32:
            raise ValueError("Key must be 256 bit long")
        if len(nonce) != 12:
            raise ValueError("Nonce must be 96 bit long")
        self.key = []
        self.nonce = []
        self.counter = counter
        self.rounds = rounds

        # convert bytearray key and nonce to little endian 32 bit unsigned ints
        self.key = ChaCha._bytearray_to_words(key)
        self.nonce = ChaCha._bytearray_to_words(nonce)

    def encrypt(self, plaintext):
        """Encrypt the data"""
        encrypted_message = bytearray()
        for i, block in enumerate(plaintext[i:i+64] for i
                                  in range(0, len(plaintext), 64)):
            key_stream = self.key_stream(i)
            encrypted_message += bytearray(x ^ y for x, y
                                           in izip(key_stream, block))

        return encrypted_message

    def key_stream(self, counter):
        """receive the key stream for nth block"""
        key_stream = ChaCha.chacha_block(self.key,
                                         self.counter + counter,
                                         self.nonce,
                                         self.rounds)
        key_stream = ChaCha.word_to_bytearray(key_stream)
        return key_stream

    def decrypt(self, ciphertext):
        """Decrypt the data"""
        return self.encrypt(ciphertext)

    def ImgEncrypt(self, plainimg):
        """Encrypts image data"""
        enc_img = self.encrypt(plainimg)

        return enc_img

    def ImgDecrypt(self, cipherimg):
        """Decrypts image data"""
        img = self.decrypt(cipherimg)

        return img

# Driver code
# def main():
    # key = os.urandom(32)
    # nonce = os.urandom(12)

    # img = 'pic1.jpg'

    # encryptor = ChaCha(key, nonce)

    # img_file = open(img, 'rb')
    # img_data = img_file.read()
    # img_file.close()
    # enc_img = encryptor.ImgEncrypt(img_data)
    # # print(res)
    # enc_file = open(img + ".enc", "wb")
    # enc_file.write(enc_img)
    # enc_file.close()

    # dec_file = open(img + '.enc', 'rb')
    # dec_img = dec_file.read()
    # dec_file.close()
    # res = encryptor.ImgDecrypt(dec_img)

    # img_stream = io.BytesIO(res)

    # img_file = PIL.Image.open(img_stream)
    # img_file.save('out_' + img)
    # print(res)



    # plaintext = b'Hello World'
    # print("Plaintext:", plaintext)
    # ciphertext = encryptor.encrypt(plaintext)
    # print("Ciphertext:", ciphertext)
    # message = encryptor.decrypt(ciphertext)
    # print("Decrypted text:", message)

# main()


