# This code is a Python port of https://github.com/rfjakob/eme with a look at https://github.com/alexey-lapin/eme-java
try:
    from Cryptodome.Cipher import AES
except ImportError:
    from Crypto.Cipher import AES

class AES256_EME:
    "AES-256 ECB-Mix-ECB or Encrypt-Mix-Encrypt mode (Halevi-Rogaway, 2003)"
    def __init__ (p, key):
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
