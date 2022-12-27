from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
import os
import random
#from secret import FLAG

KEY = b'H\xd2\xf8g(X0\x18vzF\xbc\xda\x81\n<'
IV = b'\xd3%\tY\xdc\xc4/\x1a\xaaT\xd5\xc6\xe5\x8bH\x99'

def xorPub(a, b):
        return bytes([aa ^ bb for aa, bb in zip(a, b)])

class AESWCM:

    def __init__(self, key):
        self.key = key
        self.cipher = AES.new(self.key, AES.MODE_ECB)
        self.BLOCK_SIZE = 16

    def pad(self, pt):
        if len(pt) % 16 != 0:
            pt = pad(pt, 16)
        return pt

    def blockify(self, message):
        return [
            message[i:i + 16]
            for i in range(0, len(message), 16)
        ]

    def xor(self, a, b):
        return bytes([aa ^ bb for aa, bb in zip(a, b)])

    def encrypt(self, pt, iv):
        pt = self.pad(pt)
        blocks = self.blockify(pt)
        xor_block = iv

        ct = []
        print("Block(s): ")
        print("\t" + str(blocks))
        for block in blocks:
            ct_block = self.cipher.encrypt(self.xor(block, xor_block))
            xor_block = self.xor(block, ct_block)
            ct.append(ct_block)

        # print("\nCT BLOCK: ")
        # print(ct_block)
        # print("")
        return b"".join(ct).hex()

    def decrypt(self, ct, iv):
        ct = bytes.fromhex(ct)
        blocks = self.blockify(ct)
        xor_block = iv

        pt = []
        for block in blocks:
            pt_block = self.xor(self.cipher.decrypt(block), xor_block)
            xor_block = self.xor(block, pt_block)
            pt.append(pt_block)

        return b"".join(pt)

    def tag(self, pt, iv=os.urandom(16)):
        # print(pt)
        blocks = self.blockify(bytes.fromhex(self.encrypt(pt, iv)))
        #random.shuffle(blocks)

        ct = blocks[0]
        # print("\nNUMBER OF BLOCKS: " + str(len(blocks)) + "\n")

        print("Block(s): ")
        print("\t" + str(blocks))
        for i in range(1, len(blocks)):
            ct = self.xor(blocks[i], ct)

        return ct.hex()


def main():
    aes = AESWCM(KEY)
    tags = []
    characteristics = []
    print("What properties should your magic wand have?")
    message = "Property: "


    char1 = bytes.fromhex("000000000000")
    char2 = bytes.fromhex("00000000000011111111111111111111111111111111")
    char3 = bytes.fromhex("000000000000111111111111111111111111111111113ee814bb963ee314c093c6e312b634a0")

    chars = [char1, char2, char3]

    counter = 0
    while counter < 3:
        characteristic = chars[counter]
        if characteristic not in characteristics:
            characteristics.append(characteristic)
            print("\n\nProperty Number " + str(counter) + ":")
            print("Passed Message:")
            print("\t" + str(message.encode() + characteristic))
            characteristic_tag = aes.tag(message.encode() + characteristic, IV)
            tags.append(characteristic_tag)
            print("Characteristic Tag Hex:")
            print("\t" + str(characteristic_tag))

            # print("\nCharacteristic Tag Converted:")
            # cTag_conv = bytes.fromhex(characteristic_tag)
            # print(cTag_conv)

            # IV_test = xorPub(cTag_conv, message.encode() + characteristic)
            # print("\nIV: ")
            # print(IV)

            # print("\nIV TEST:")
            # print(IV_test)
            
            # if IV_test == IV:
            #     print("SUCCESS")
            # else:
            #     print("FAILURE")

            #exit()

            if len(tags) > len(set(tags)):
                print("WHATEVER YOU JUST DID WAS RIGHT")

            counter += 1
        else:
            print("Only different properties are allowed!")
            exit(1)


if __name__ == "__main__":
    main()
