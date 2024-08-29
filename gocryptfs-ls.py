#!/usr/bin/python3
import argparse
import getpass
import sys
import os
from struct import pack

from gocryptfs import GocryptfsConfig, decode_masterkey
from aes256eme import AES256_EME

try:
    from Cryptodome.Protocol.KDF import HKDF
    from Cryptodome.Cipher import AES
    from Cryptodome.Hash import SHA256
except ImportError:
    from Crypto.Protocol.KDF import HKDF
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA256

# Helper functions

def get_emekey(masterkey):
    key = HKDF(masterkey, salt=b"", key_len=32, hashmod=SHA256,
               context=b"EME filename encryption")
    return key

def unb64(s, fmt=4):
    "Base64 decode"
    i = 0
    result = bytearray()
    alphabet = bytearray(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/')
    if fmt & 4:
        alphabet = alphabet.replace(b'+/', b'-_')
    for c in s:
        if c in (61,10,13): continue
        n = alphabet.find(pack('B',c))
        if n < 0:
            raise BaseException("BAD INPUT '%s'"%c)
        if i == 0: # push 6 bits
            j = n << 2
        elif i == 1: # pop 6, pick 2, push 4
            j |= ((n & 0b110000) >> 4)
            result += pack('B',j)
            j = (n & 0b001111) << 4
        elif i == 2: # pop 4, pick 4, push 2
            j |= ((n & 0b111100) >> 2)
            result += pack('B',j)
            j = (n & 0b11) << 6
        elif i == 3: # pop 2, pick 6
            j |= n
            result += pack('B',j)
        i = (i+1)%4
    return result

def pad16(s):
    "PKCS#7 padding"
    blocks = (len(s)+15) // 16
    added = blocks*16 - len(s)
    r = bytearray(added.to_bytes()) * (blocks*16)
    r[:len(s)] = s # s must be bytes
    return r

def unpad16(s):
    z = bytearray()
    for c in s:
        if c <= 16: break
        z += c.to_bytes()
    return z

def name_decode(eme, name):
    "Decodes the full pathname 'name'"
    diriv_f = os.path.join(os.path.dirname(name), 'gocryptfs.diriv')
    try:
        diriv = open(diriv_f, 'rb').read()
    except:
        print('note: could not open', diriv_f)
        diriv = b''
    if len(diriv) != 16:
        print('note: corrupted gocryptfs.diriv')
        return b''
    bname = os.path.basename(name)
    bname = unb64(bytes(bname,'utf-8'))
    bname = eme.decrypt_iv(diriv, bname)
    bname = unpad16(bname)
    try:
        bname = bname.decode()
    except UnicodeDecodeError:
        print('warning: could not decode', name)
    return bname



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="List decoded filenames in a gocryptfs volume")
    parser.add_argument('--aessiv', action='store_true', help="AES-SIV encryption")
    parser.add_argument('--masterkey', type=decode_masterkey, help="Masterkey as hex string representation")
    parser.add_argument('--password', help="Password to unlock config file")
    parser.add_argument('--config', help="Path to gocryptfs.conf configuration file")
    parser.add_argument('path', help="Encrypted directory to list from")
    args = parser.parse_args()

    if not os.path.isdir(args.path):
        print('You must pass a directory path!')
        sys.exit(1)

    if args.masterkey is None:
        config = GocryptfsConfig(filename=args.config, basepath=args.path)
        if args.password is None:
            args.password = getpass.getpass('Password: ')
        args.masterkey = config.get_masterkey(args.password)
        args.aessiv = config.aessiv

    args.emekey = get_emekey(args.masterkey)
    
    eme = AES256_EME(args.emekey)
    
    for root, dirs, files in os.walk(args.path):
        if root != args.path:
            droot = name_decode(eme, root)
        else:
            droot = root
        print ('   Directory contents of "%s" -> "%s":\n' % (root, droot))
        for it in files+dirs:
            if it in ['gocryptfs.conf', 'gocryptfs.diriv']: continue
            if it.startswith('gocryptfs.longname.'):
                if not it.endswith('.name'): continue
                # replace the longname with the base64 string found inside that file
                it = open(os.path.join(root, it)).read()
            pname = os.path.join(root, it)
            print('%s -> %s' % (it, name_decode(eme, pname)))
        print('\n')
