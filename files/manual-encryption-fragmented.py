#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypt a wep message given the WEP key"""
import string

from scapy.all import *
import binascii
from rc4 import RC4
import argparse
import zlib
import random

from scapy.layers.dot11 import RadioTap

fragments_num = 3

parser = argparse.ArgumentParser()

parser.add_argument("--interface", default="wlan0mon", help="Interface to use")
parser.add_argument("--output", default="output-fragmented.cap", type=str, help="Output file name")
parser.add_argument("--key", default="AAAAAAAAAA", type=str, help="Key used to encrypt, with no space or ':' ")

args = parser.parse_args()
interface = args.interface
file = args.output
print(args.key)

key = binascii.unhexlify(args.key)
print(key)

template = rdpcap('arp.cap')[0]

# The message that I want to encrypt
texts = []
text1 = randstring(36)
text2 = randstring(36)
text3 = randstring(36)

print(text1)
print(text2)
print(text3)

texts.append(text1)
texts.append(text2)
texts.append(text3)

# Explanation : The reason I chose to "overload" the above portion of code is that I generate random texts. If I want
# to print them and compare the encrypted and decrypted values, I need to do so. Otherwise, I would use : texts = [
# randstring(36), randstring(36), randstring(36)] and it would be much easier on the eye

# IV
iv = template.iv

# The rc4 seed is composed by the IV+key
seed = iv + key

# We create an instance of RC4 using our seed
cipher = RC4(seed, streaming=False)

fragments = []

for i in range(fragments_num):
    fragment = template.copy()

    # ICV
    icv = zlib.crc32(texts[i])
    to_enc_icv = struct.pack('<L', icv)

    # msg + icv
    to_encrypt = texts[i] + to_enc_icv

    # to_encrypt = message+icv
    encrypted = cipher.crypt(to_encrypt)

    # restructuring the ICV
    icv_num = encrypted[-4:]
    icv_num = struct.unpack('!L', icv_num)[0]

    # forging the packet
    fragment.wepdata = encrypted[:-4]
    fragment.icv = icv_num
    fragment[RadioTap].len = None
    fragment.SC += i

    if i == fragments_num:
        fragment.FCfield = 0x841
    else:
        fragment.FCfield = 0x845

    fragments.append(fragment)

# writing the pcap file
wrpcap(file, fragments)
print("Output stored in ./" + file)

# sending the packet
# sendp(arp, iface=interface)
print("Manually encrypted packet send.")


def randomString(stringlength=36):
    """Generate a random string of fixed length """
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringlength))
