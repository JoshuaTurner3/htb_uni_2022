from pwn import *

message = "Property: "

def xor(a, b):
        return bytes([aa ^ bb for aa, bb in zip(a, b)])

# def blockify(message):
#     return [
#         message[i:i + 16]
#         for i in range(0, len(message), 16)
#     ]

block1 = b'Property: \x00\x00\x00\x00\x00\x00'
block2 = b'\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11'

# char1 = bytes.fromhex("000000000000")
# char2 = bytes.fromhex("00000000000011111111111111111111111111111111")
# char3 = bytes.fromhex("0000000000001111111111111111111111111111111111111111111111111111111111111111")

# FIRST INPUT
# 000000000000
# SECOND INPUT
# 00000000000011111111111111111111111111111111

# GET THIS FROM THE SERVER
ct1_hex = "3ea94a73f37d7a37a195e2ed066a46e3"
ct1 = bytes.fromhex(ct1_hex)

xor2 = xor(block1, ct1)

# GET THIS FROM THE SERVER
hash2_hex = "d35ee132580b4d60d860c3308379389c"
hash2 = bytes.fromhex(hash2_hex)

ct2 = xor(hash2, ct1)
xor3 = xor(block2, ct2)
desired = xor(block2, xor2)
ans = xor(desired, xor3)

#print(ans)
# THIRD INPUT IS THE SECOND + THE FOLLOWING
# 832c8e423d793919e240c3308379389c
print(str(ans.hex()))
