import os, sys, platform, struct, shutil, subprocess, string, warnings, hashlib, secrets, math

from ctypes import *
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

resources_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'resources')

def readle(b):
    return int.from_bytes(b, 'little')

def readbe(b):
    return int.from_bytes(b, 'big')

def int8tobytes(x):
    return int.to_bytes(x, 1, sys.byteorder)

def int16tobytes(x):
    return int.to_bytes(x, 2, sys.byteorder)

def int32tobytes(x):
    return int.to_bytes(x, 4, sys.byteorder)

def int64tobytes(x):
    return int.to_bytes(x, 8, sys.byteorder)

def byteswap32(i):
    return struct.unpack("<I", struct.pack(">I", i))[0]

def hextobytes(s):
	return bytes.fromhex(s)

def read_chunks(f, size, chunk_size=0x10000):
    for _ in range(size // chunk_size):
        yield f.read(chunk_size)

    yield f.read(size % chunk_size)

def align(size, alignment): # Returns (min) number needed to be added to 'size' so 'size' is a multiple of 'alignment'
	if size % alignment != 0:
		return alignment - (size % alignment)
	else:
		return 0

def roundup(size, alignment):
	if size % alignment != 0:
		return size + alignment - (size % alignment)
	else:
		return size

class Crypto:
	def sha256(f, size, chunk_size=0x10000):
		h = hashlib.sha256()
		for _ in range(size // chunk_size):
			h.update(f.read(chunk_size))
		h.update(f.read(size % chunk_size))
		return h.digest()

	def sign_rsa_sha256(mod: bytes, priv: bytes, data: bytes):
		x = pkcs1_15.new(RSA.construct((readbe(mod), 0x10001, readbe(priv))))
		h = SHA256.new(data)
		sig = x.sign(h)
		return sig
	
	def verify_rsa_sha256(mod: bytes, data: bytes, sig: bytes):
		x = pkcs1_15.new(RSA.construct((readbe(mod), 0x10001)))
		h = SHA256.new(data)
		try:
			x.verify(h, sig)
			return True
		except (ValueError, TypeError):
			return False
