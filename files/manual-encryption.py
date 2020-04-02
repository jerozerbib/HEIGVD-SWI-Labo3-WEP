#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypt a wep message given the WEP key"""

from scapy.all import *
import binascii
from rc4 import RC4
import argparse
import zlib

from scapy.layers.dot11 import RadioTap

parser = argparse.ArgumentParser()

# Default message is a random 36 bytes long string
parser.add_argument("--message", default="zrwkttmdoophhogdzddfbgtrfwmihztxhtmo", type=str, help="Message to encrypt. "
                                                                                                "Must be 36 bytes "
                                                                                                "long")
parser.add_argument("--interface", default="wlan0mon", help="Interface to use")
parser.add_argument("--output", default="output.cap", type=str, help="Output file name")
parser.add_argument("--key", default="AAAAAAAAAA", type=str, help="Key used to encrypt, with no space or ':' ")

args = parser.parse_args()
interface = args.interface
file = args.output
print(args.key)

key = binascii.unhexlify(args.key)
print(key)

arp = rdpcap('arp.cap')[0]

# The message that I want to encrypt
message = args.message.encode()

# ICV
icv = zlib.crc32(message)
to_enc_icv = struct.pack('<L', icv)

# msg + icv
to_encrypt = message + to_enc_icv

# IV
iv = arp.iv

# The rc4 seed is composed by the IV+key
seed = iv + key

# We create an instance of RC4 using our seed
cipher = RC4(seed, streaming=False)

# to_encrypt = message+icv
encrypted = cipher.crypt(to_encrypt)

# restructuring the ICV
icv_num = encrypted[-4:]
icv_num = struct.unpack('!L', icv_num)[0]

# forging the packet
arp.wepdata = encrypted[:-4]
arp.icv = icv_num
arp[RadioTap].len = None

# arp.show()

# writing the pcap file
wrpcap(file, arp)
print("Output stored in ./" + file)

# sending the packet
# sendp(arp, iface=interface)
print("Manually encrypted packet send.")
