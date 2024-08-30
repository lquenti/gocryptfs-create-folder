#!/usr/bin/python3
import argparse
import getpass
import sys
import os
import base64
from struct import pack

from gocryptfs import GocryptfsConfig, decode_masterkey
from aes256eme import AES256_EME

try:
    from Cryptodome.Protocol.KDF import HKDF
    from Cryptodome.Cipher import AES
    from Cryptodome.Hash import SHA256
    from Cryptodome.Random import Random
except ImportError:
    from Crypto.Protocol.KDF import HKDF
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA256
    from Crypto import Random

PLAINTEXT_ZERO = b"\x00" * 4096
CIPHERTEXT_ZERO = b"\x00" * (4096 + 32)

# Helper functions

def get_emekey(masterkey):
    key = HKDF(masterkey, salt=b"", key_len=32, hashmod=SHA256,
               context=b"EME filename encryption")
    return key

def pad16(s):
    "PKCS#7 padding"
    blocks = (len(s)+15) // 16
    added = blocks*16 - len(s)
    r = bytearray(added.to_bytes()) * (blocks*16)
    r[:len(s)] = s # s must be bytes
    return r

def name_encode(eme, name):
    "Encodes the full pathname 'name'"
    diriv_f = os.path.join(os.path.dirname(name), 'gocryptfs.diriv')
    diriv = open(diriv_f, 'rb').read()
    if len(diriv) != 16:
        raise BaseException('invalid gocryptfs.diriv')
    bname = os.path.basename(name).encode()
    bname = pad16(bname)
    bname = eme.encrypt_iv(diriv, bname)
    # gocryptfs driver does not like '=' in base64 encoded names; base64 module dislikes their absence
    bname = base64.urlsafe_b64encode(bname).strip(b'=').decode()
    return bname

def encrypt_gcm_block(key, blockno, fileid, block):
    "Encrypts a 4KiB plaintext block in GCM mode"
    if block == PLAINTEXT_ZERO:
        return CIPHERTEXT_ZERO
    # Layout: [ NONCE | CIPHERTEXT (...) |  TAG  ]
    nonce = Random.get_random_bytes(16)
    o = AES.new(key, AES.MODE_GCM, nonce=nonce)
    o.update(pack(">Q", blockno) + fileid)
    eblock, tag = o.encrypt_and_digest(block)
    return nonce + eblock + tag



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Replace a plain file in a gocryptfs volume with its encrypted version")
    parser.add_argument('--aessiv', action='store_true', help="AES-SIV encryption")
    parser.add_argument('--masterkey', type=decode_masterkey, help="Masterkey as hex string representation")
    parser.add_argument('--password', help="Password to unlock config file")
    parser.add_argument('--config', help="Path to gocryptfs.conf configuration file")
    parser.add_argument('pathname', help="pathname of the unencrypted file to process")
    args = parser.parse_args()

    if os.path.isdir(args.pathname):
        print('You must pass a file pathname!')
        sys.exit(1)
    if not os.path.exists(args.pathname):
        print('Specified pathname does not exist!')
        sys.exit(1)

    if args.masterkey is None:
        config = GocryptfsConfig(filename=args.config, basepath=args.pathname)
        if args.password is None:
            args.password = getpass.getpass('Password: ')
        args.masterkey = config.get_masterkey(args.password)
        args.aessiv = config.aessiv

    args.emekey = get_emekey(args.masterkey)
    eme = AES256_EME(args.emekey)
    key = HKDF(args.masterkey, salt=b"", key_len=32, hashmod=SHA256,
        context=b"AES-GCM file content encryption")

    fpin = open(args.pathname, 'rb')

    ename = name_encode(eme, args.pathname)
    # handle very long encoded names
    if len(ename) > 255:
        # gets the SHA-256 hash, base64 encoded, of the encrypted longname
        hash = base64.urlsafe_b64encode(SHA256.new(ename.encode()).digest()).strip(b'=').decode()
        # stores the encrypted longname
        lname = os.path.join(os.path.dirname(args.pathname), 'gocryptfs.longname.%s.name'%hash)
        open(lname, 'w').write(ename)
        # replace with the fake shortname
        ename = 'gocryptfs.longname.' + hash
    ename = os.path.join(os.path.dirname(args.pathname), ename)
    fpout = open(ename, 'wb')
    fpout.write(b'\x00\x02') # magic couple
    fileid = Random.get_random_bytes(16) # random 128-bit FileID
    fpout.write(fileid)

    n = 0
    while True:
        buf = fpin.read(4096)
        if not buf: break
        fpout.write(encrypt_gcm_block(key, n, fileid, buf))
        n += 1

    fpin.close()
    fpout.close()
    os.remove(args.pathname)
    print('Done.')
