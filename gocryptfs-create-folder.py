#/usr/bin/env python3

# gocryptfs-create-folder
#
# Creates a gocryptfs folder based on a plain folder without relying on
# gocryptfs/FUSE.
#
# Link to Repository: <https://codeberg.org/LGLQ/gocryptfs-create-folder>
# SPDX Identifier: MIT

import argparse
import base64
import getpass
import hashlib
import json
import os
import re
import socket
import struct
import sys

from struct import pack

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


class AES256_EME:
    "AES-256 ECB-Mix-ECB or Encrypt-Mix-Encrypt mode (Halevi-Rogaway, 2003)"
    def __init__(p, key):
        if not key:
            raise BaseException("must pass a valid key")
        if len(key) != 32:
            raise BaseException("must pass a 256-bit AES key")
        p.key = key

    def _decrypt(p, s):
        return AES.new(p.key, AES.MODE_ECB).decrypt(s)

    def _encrypt(p, s):
        return AES.new(p.key, AES.MODE_ECB).encrypt(s)

    def decrypt_iv(p, iv, s):
        return p.transform(iv, s)

    def encrypt_iv(p, iv, s):
        return p.transform(iv, s, 'enc')

    """Transform - EME-encrypt or EME-decrypt, according to "direction"
    The data in "inputData" is en- or decrypted with the block ciper under
    "tweak" (also known as IV).

    The tweak is used to randomize the encryption in the same way as an
    IV.  A use of this encryption mode envisioned by the authors of the
    algorithm was to encrypt each sector of a disk, with the tweak
    being the sector number.  If you encipher the same data with the
    same tweak you will get the same ciphertext.

    The result is returned in a freshly allocated slice of the same
    size as inputData.

    Limitations:
     * The block cipher must have block size 16 (usually AES).
     * The size of "tweak" must be 16
     * "inputData" must be a multiple of 16 bytes long
     If any of these pre-conditions are not met, the function will panic."""
    def transform(p, tweak, inputData, direction='dec'):
        "Main transformation routine"
        T = tweak
        P = inputData
        if len(T) != 16:
            raise BaseException("tweak must be 16 bytes long")
        if len(P)%16:
            raise BaseException("data length must be a 16 bytes multiple")
        m = len(P) // 16
        if not m or m > 16 * 8:
            raise BaseException("data must be from 1 to 128 blocks long")
        fu = p._decrypt
        if direction != 'dec':
            fu = p._encrypt

        C = bytearray(len(P))
        LTable = p.tabulateL(m)

        for j in range(m):
            Pj = inputData[j*16:j*16+16]
            PPj = p.xorBlocks(Pj, LTable[j])
            out = fu(PPj)
            n = len(out)
            C[j*16:j*16+n] = out[:n]

        CView = bytearray(16)
        CView[:16] = C[:16]
        MP = p.xorBlocks(CView, T)
        for j in range(1, m):
            CView[:16] = C[j*16:j*16+16]
            MP = p.xorBlocks(MP, CView)

        MC = fu(MP)
        M = p.xorBlocks(MP, MC)

        for j in range(1, m):
            M = p.multByTwo(M)
            CView[:16] = C[j*16:j*16+16]
            CCCj = p.xorBlocks(CView, M)
            C[j*16:j*16+16] = CCCj[:16]

        CCC1 = p.xorBlocks(MC, T)
        for j in range(1, m):
            CView[:16] = C[j*16:j*16+16]
            CCC1 = p.xorBlocks(CCC1, CView)

        C[:16] = CCC1[:16]
        for j in range(m):
            CView[:16] = C[j*16:j*16+16]
            C[j*16:j*16+16] = fu(CView)
            CView[:16] = C[j*16:j*16+16]
            C[j*16:j*16+16] = p.xorBlocks(CView, LTable[j])

        return C

    # tabulateL - calculate L_i for messages up to a length of m cipher blocks
    def tabulateL(p, m):
        eZero = bytearray(16)
        Li = p._encrypt(eZero)
        LTable = []
        for i in range(m):
            Li = p.multByTwo(Li)
            LTable +=  [Li]
        return LTable

    def xorBlocks(p, b1, b2):
        if len(b1) != len(b2):
            raise BaseException("blocks size must be equal")
        n = len(b1)
        res = bytearray(n)
        for i in range(n):
            res[i] = b1[i] ^ b2[i]
        return res

    # multByTwo - GF multiplication as specified in the EME-32 draft
    def multByTwo(p, s):
        if len(s) != 16:
            raise BaseException("input must be 16 bytes long")
        res = bytearray(16)
        res[0] = (s[0] * 2) & 0xFF # force 8-bit
        if s[15] >= 128: # if negative byte
            res[0] ^= 135
        for j in range(1, 16):
            res[j] = (s[j] * 2) & 0xFF
            if s[j-1] >= 128:
                res[j] += 1
        return res


def get_emekey(masterkey):
    key = HKDF(masterkey, salt=b"", key_len=32, hashmod=SHA256,
               context=b"EME filename encryption")
    return key


def pad16(s):
    "PKCS#7 padding"
    blocks = (len(s)+15) // 16
    added = blocks*16 - len(s)
    r = bytearray(added.to_bytes()) * (blocks*16)
    r[:len(s)] = s  # s must be bytes
    return r


def name_encode(eme, outputfile):
    "Encodes the full pathname 'name'"
    diriv_f = os.path.join(os.path.dirname(outputfile), 'gocryptfs.diriv')
    diriv = open(diriv_f, 'rb').read()
    if len(diriv) != 16:
        raise BaseException('invalid gocryptfs.diriv')
    bname = os.path.basename(outputfile).encode()
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


def parse_cli_or_die():
    parser = argparse.ArgumentParser(
        description="Creates a gocryptfs folder based on a plain folder without relying on gocryptfs/FUSE."
    )
    parser.add_argument("OUTPUTDIR", help="Path to the (empty) gocryptfs cipher dir output)")
    parser.add_argument("INPUTDIR", help="Path to the unencrypted input files to be encrypted")

    args = parser.parse_args()
    outputdir = args.OUTPUTDIR
    inputdir = args.INPUTDIR

    # Sanity checks
    if not os.path.exists(outputdir):
        print(f"Error: Output directory '{outputdir}' does not exist.")
        sys.exit(1)
    if not os.path.isdir(outputdir):
        print(f"Error: Output path '{outputdir}' is not a directory.")
        sys.exit(1)
    if os.listdir(outputdir):
        print(f"Error: Output directory '{outputdir}' is not empty.")
        sys.exit(1)

    if not os.path.exists(inputdir):
        print(f"Error: Input directory '{inputdir}' does not exist.")
        sys.exit(1)
    if not os.path.isdir(inputdir):
        print(f"Error: Input path '{inputdir}' is not a directory.")
        sys.exit(1)
    if not os.listdir(inputdir):
        print(f"Error: Input directory '{inputdir}' is empty.")
        sys.exit(1)

    return outputdir, inputdir


def get_user_password():
    while True:
        password = getpass.getpass('Password: ')
        confirm_password = getpass.getpass('Repeat: ')
        if password == confirm_password:
            return password
        print("Passwords are not the same")


def create_gocryptfs_conf(inputdir, password: str):
    """
    This is an example `gocryptfs.conf`:
    ```
    {
        "Creator": "gocryptfs v...",
        "EncryptedKey": "B64 encoded key",
        "ScryptObject": {
            "Salt": "b64 encoded 32 byte salt",
            "N": 65536,
            "R": 8,
            "P": 1,
            "KeyLen": 32
        },
        "Version": 2,
        "FeatureFlags": [
            "HKDF",
            "GCMIV128",
            "DirIV",
            "EMENames",
            "LongNames",
            "Raw64"
        ]
    }
    ```
    Since we _create_ and don't _read_ existing ones, we can hard code all
    FeatureFlags and Version
    """
    KEY_LEN = 32
    master_key = os.urandom(KEY_LEN)
    scrypt_salt = os.urandom(KEY_LEN)
    scrypt_n = 65536
    scrypt_r = 8
    scrypt_p = 1

    # See <https://nuetzlich.net/gocryptfs/forward_mode_crypto/>
    # Layout: [ NONCE | CIPHERTEXT (...) |  TAG  ]
    scrypt_key = hashlib.scrypt(
        password.encode('utf-8'),
        salt=scrypt_salt,
        n=scrypt_n,
        r=scrypt_r,
        p=scrypt_p,
        maxmem=0x7fffffff,  # Copied from gocryptfs-inspect
        dklen=KEY_LEN
    )
    nonce = os.urandom(16)
    aes_key = HKDF(
        scrypt_key,
        key_len=KEY_LEN,
        salt=b"",
        hashmod=SHA256,
        context=b"AES-GCM file content encryption"   # See: cryptocore/hkdf.go
    )
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    cipher.update(struct.pack(">Q", 0))  # Additional authenticated data
    ciphertext, tag = cipher.encrypt_and_digest(master_key)
    encrypted_key_bytes = nonce + ciphertext + tag

    encrypted_key_b64 = base64.b64encode(encrypted_key_bytes).decode('utf-8')
    scrypt_salt_b64 = base64.b64encode(scrypt_salt).decode('utf-8')
    config_dict = {
        "Creator": "gocryptfs-create-conf 1.0 <https://codeberg.org/LGLQ/gocryptfs-create-folder>",
        "EncryptedKey": encrypted_key_b64,
        "ScryptObject": {
            "Salt": scrypt_salt_b64,
            "N": scrypt_n,
            "R": scrypt_r,
            "P": scrypt_p,
            "KeyLen": KEY_LEN
        },
        "Version": 2,
        "FeatureFlags": [
            "HKDF",
            "GCMIV128",
            "DirIV",
            "EMENames",
            "LongNames",
            "Raw64"
        ]
    }

    with open(os.path.join(inputdir, "gocryptfs.conf"), "w") as fp:
        json.dump(config_dict, fp, indent=4)

    return master_key


def create_gocryptfs_diriv(inputdir):
    with open(os.path.join(inputdir, "gocryptfs.diriv"), "wb") as fp:
        fp.write(os.urandom(16))


def get_all_relative_folders(root_folder):
    relative_folders = []
    for dirpath, dirnames, _ in os.walk(root_folder):
        for dirname in dirnames:
            full_path = os.path.join(dirpath, dirname)
            relative_path = os.path.relpath(full_path, root_folder)
            relative_folders.append(relative_path)
    return relative_folders


def get_all_relative_files(root_folder):
    relative_files = []
    for dirpath, _, filenames in os.walk(root_folder, topdown=True):
        for filename in filenames:
            full_path = os.path.join(dirpath, filename)
            relative_path = os.path.relpath(full_path, root_folder)
            relative_files.append(relative_path)
    return relative_files


def create_folders_with_diriv(inputdir, outputdir):
    relative_folders = get_all_relative_folders(inputdir)
    for rf in relative_folders:
        new_absolute_path = os.path.join(outputdir, rf)
        os.makedirs(new_absolute_path, exist_ok=True)
        create_gocryptfs_diriv(new_absolute_path)


def encrypt_file(master_key, inputfile, outputfile):
    eme_key = get_emekey(master_key)
    eme = AES256_EME(eme_key)
    key = HKDF(master_key, salt=b"", key_len=32, hashmod=SHA256,
               context=b"AES-GCM file content encryption")

    with open(inputfile, 'rb') as fpin:
        ename = name_encode(eme, outputfile)

        # Handle very long encoded names
        if len(ename) > 255:
            # gets the SHA-256 hash, base64 encoded, of the encrypted longname
            hash = base64.urlsafe_b64encode(SHA256.new(ename.encode()).digest()).strip(b'=').decode()
            # stores the encrypted longname
            lname = os.path.join(os.path.dirname(outputfile), f"gocryptfs.longname.{hash}.name")
            with open(lname, "w") as fp:
                fp.write(ename)
            # replace with the fake shortname
            ename = 'gocryptfs.longname.' + hash

        ename = os.path.join(os.path.dirname(outputfile), ename)
        with open(ename, 'wb') as fpout:
            fpout.write(b'\x00\x02')  # magic couple
            fileid = os.urandom(16)
            fpout.write(fileid)

            n = 0
            while True:
                buf = fpin.read(4096)
                if not buf:
                    break
                fpout.write(encrypt_gcm_block(key, n, fileid, buf))
                n += 1


def main():
    outputdir, inputdir = parse_cli_or_die()
    password = get_user_password()

    master_key = create_gocryptfs_conf(outputdir, password)
    create_gocryptfs_diriv(outputdir)

    # First create the folders, then fill with files
    # TODO folder encryption missing, thus flat files for now
    # create_gocryptfs_diriv(inputdir, outputdir)
    for rf in get_all_relative_files(inputdir):
        print("Processing", rf)
        ipath = os.path.join(inputdir, rf)
        opath = os.path.join(outputdir, rf)
        print(f"{ipath=}")
        print(f"{opath=}")
        encrypt_file(master_key, ipath, opath)


if __name__ == "__main__":
    main()
