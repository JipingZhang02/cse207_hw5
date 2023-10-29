from sage.all import *
import struct
import re
import base64
from Crypto.Cipher import AES
from Crypto import Random

key_header = '-----BEGIN PRETTY BAD PUBLIC KEY BLOCK-----\n'
key_footer = '-----END PRETTY BAD PUBLIC KEY BLOCK-----\n'

def b64_enc(s):
    return base64.encodebytes(s).decode("ascii")

def b64_dec(s):
    return base64.b64decode(s)

# Generate ElGamal public key (p,g,y=g^x mod p) in standardized PBP Diffie-Hellman group
def gen_public_key():
    p = 0x3cf2a66e5e175738c9ce521e68361676ff9c508e53b6f5ef1f396139cbd422d9f90970526fd8720467f17999a6456555dda84aa671376ddbe180902535266d383
    R = Integers(p)
    g = R(2)
    x = ZZ.random_element(2**128)
    y = g**x

    key = int_to_mpi(p)+int_to_mpi(g)+int_to_mpi(y)
    return key_header + b64_enc(key) + key_footer

# Our "MPI" format consists of 4-byte integer length l followed by l bytes of binary key
def int_to_mpi(z):
    s = int_to_binary(z)
    return struct.pack('<I',len(s))+s

# Get bytes representation of arbitrary-length long int
def int_to_binary(z):
    z = int(z)
    return z.to_bytes((z.bit_length() + 7) // 8, 'big')

# Read one MPI-formatted value beginning at s[index]
# Returns value and index + bytes read.
def parse_mpi(s,index):
    length = struct.unpack('<I',s[index:index+4])[0]
    xbytes = s[index+4:index+4+length]
    z = Integer(int.from_bytes(xbytes, 'big'))
    return z, index+4+length

# An ElGamal public key consists of a magic header and footer enclosing the MPI-encoded values for p, g, and y.
def parse_public_key(s):
    data = re.search(key_header+"(.*)"+key_footer,s,flags=re.DOTALL).group(1)
    data = b64_dec(data)
    index = 0
    p,index = parse_mpi(data,index)
    g,index = parse_mpi(data,index)
    y,index = parse_mpi(data,index)
    return {'p':p, 'g':g, 'y':y}

encrypt_header = '-----BEGIN PRETTY BAD ENCRYPTED MESSAGE-----\n'
encrypt_footer = '-----END PRETTY BAD ENCRYPTED MESSAGE-----\n'

# PKCS 7 pad message.
def pad(s,blocksize=AES.block_size):
    n = blocksize-(len(s)%blocksize)
    return s+bytes([n]*n)

# Encrypt string s using ElGamal encryption with AES in CBC mode.
# Generate a 128-bit symmetric key, encrypt it using ElGamal, and prepend the MPI-encoded ElGamal ciphertext to the AES-encrypted ciphertext of the message.
def encrypt(pubkey,s):
    p = pubkey['p']; R = Integers(p)
    g = R(pubkey['g']); y = R(pubkey['y'])
    k = ZZ.random_element(2**128)
    m = ZZ.random_element(2**128)

    output = int_to_mpi(g**k)+int_to_mpi(m*(y**k))

    aeskey = int_to_binary(m)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(aeskey, AES.MODE_CBC, iv)

    output += iv + cipher.encrypt(pad(s))

    return encrypt_header + base64.b64encode(output).decode("ascii") + encrypt_footer

if __name__=='__main__':
    f = open("key.pub",'w')
    f.write(gen_public_key())
    f.close()

    plaintext = open('hw5.pdf', 'rb').read()
    pubkey = parse_public_key(open('key.pub').read())
    f = open('hw5.pdf.enc.asc','w')
    f.write(encrypt(pubkey,plaintext))
    f.close()