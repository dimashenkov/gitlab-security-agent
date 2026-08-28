



















''

from hashlib import md5, sha1
import os
from typing import Callable, Dict, Sequence, Tuple, Union

from .asn1 import ASN1DecodeError, ObjectIdentifier, der_encode, der_decode
from .crypto import BasicCipher, get_cipher_params, pbkdf2_hmac
from .misc import BytesOrStr, HashType


_Cipher = Union[BasicCipher, '_RFC1423Pad']

_PKCS8CipherHandler = Callable[[object, BytesOrStr, Callable, str], _Cipher]
_PKCS8Cipher = Tuple[_PKCS8CipherHandler, Callable, str]

_PBES2CipherHandler = Callable[[Sequence, str, bytes], _Cipher]
_PBES2Cipher = Tuple[_PBES2CipherHandler, str]

_PBES2KDFHandler = Callable[[Sequence, BytesOrStr, int], bytes]
_PBES2KDF = Tuple[_PBES2KDFHandler, Tuple[object, ...]]


_ES1_MD5_DES    = ObjectIdentifier('1.2.840.113549.1.5.3')
_ES1_SHA1_DES   = ObjectIdentifier('1.2.840.113549.1.5.10')

_ES2            = ObjectIdentifier('1.2.840.113549.1.5.13')

_P12_RC4_128    = ObjectIdentifier('1.2.840.113549.1.12.1.1')
_P12_RC4_40     = ObjectIdentifier('1.2.840.113549.1.12.1.2')
_P12_DES3       = ObjectIdentifier('1.2.840.113549.1.12.1.3')
_P12_DES2       = ObjectIdentifier('1.2.840.113549.1.12.1.4')

_ES2_CAST128    = ObjectIdentifier('1.2.840.113533.7.66.10')
_ES2_DES3       = ObjectIdentifier('1.2.840.113549.3.7')
_ES2_BF         = ObjectIdentifier('1.3.6.1.4.1.3029.1.2')
_ES2_DES        = ObjectIdentifier('1.3.14.3.2.7')
_ES2_AES128     = ObjectIdentifier('2.16.840.1.101.3.4.1.2')
_ES2_AES192     = ObjectIdentifier('2.16.840.1.101.3.4.1.22')
_ES2_AES256     = ObjectIdentifier('2.16.840.1.101.3.4.1.42')

_ES2_PBKDF2     = ObjectIdentifier('1.2.840.113549.1.5.12')

_ES2_SHA1       = ObjectIdentifier('1.2.840.113549.2.7')
_ES2_SHA224     = ObjectIdentifier('1.2.840.113549.2.8')
_ES2_SHA256     = ObjectIdentifier('1.2.840.113549.2.9')
_ES2_SHA384     = ObjectIdentifier('1.2.840.113549.2.10')
_ES2_SHA512     = ObjectIdentifier('1.2.840.113549.2.11')

_pkcs1_cipher: Dict[bytes, str] = {}
_pkcs1_dek_name: Dict[str, bytes] = {}

_pkcs8_handler: Dict[ObjectIdentifier, _PKCS8Cipher] = {}
_pkcs8_cipher_oid: Dict[Tuple[str, str], ObjectIdentifier] = {}

_pbes2_cipher: Dict[ObjectIdentifier, _PBES2Cipher] = {}
_pbes2_cipher_oid: Dict[str, ObjectIdentifier] = {}

_pbes2_kdf: Dict[ObjectIdentifier, _PBES2KDF] = {}
_pbes2_kdf_oid: Dict[str, ObjectIdentifier] = {}

_pbes2_prf: Dict[ObjectIdentifier, str] = {}
_pbes2_prf_oid: Dict[str, ObjectIdentifier] = {}


class KeyEncryptionError(ValueError):
    ''







class _RFC1423Pad:
    ''








    def __init__(self, cipher_name: str, block_size: int,
                 key: bytes, iv: bytes):
        self._cipher = BasicCipher(cipher_name, key, iv)
        self._block_size = block_size

    def encrypt(self, data: bytes) -> bytes:
        ''

        pad = self._block_size - (len(data) % self._block_size)
        data += pad * bytes((pad,))
        return self._cipher.encrypt(data)

    def decrypt(self, data: bytes) -> bytes:
        ''

        data = self._cipher.decrypt(data)

        if data:
            pad = data[-1]
            if (1 <= pad <= self._block_size and
                    data[-pad:] == pad * bytes((pad,))):
                return data[:-pad]

        raise KeyEncryptionError('Unable to decrypt key')


def _pbkdf1(hash_alg: HashType, passphrase: BytesOrStr, salt: bytes,
            count: int, key_size: int) -> bytes:
    ''











    if isinstance(passphrase, str):
        passphrase = passphrase.encode('utf-8')

    key = passphrase + salt
    for _ in range(count):
        key = hash_alg(key).digest()

    if len(key) <= key_size:
        return key + _pbkdf1(hash_alg, key + passphrase, salt, count,
                             key_size - len(key))
    else:
        return key[:key_size]


def _pbkdf_p12(hash_alg: HashType, passphrase: BytesOrStr, salt: bytes,
               count: int, key_size: int, idx: int) -> bytes:
    ''






    def _make_block(data: bytes, v: int) -> bytes:
        ''

        l = len(data)
        size = ((l + v - 1) // v) * v
        return (((size + l - 1) // l) * data)[:size]

    v = hash_alg().block_size
    D = v * bytes((idx,))

    if isinstance(passphrase, str):
        passphrase = passphrase.encode('utf-16be')

    I = bytearray(_make_block(salt, v) + _make_block(passphrase + b'\0\0', v))

    key = b''
    while len(key) < key_size:
        A = D + I
        for i in range(count):
            A = hash_alg(A).digest()

        B = int.from_bytes(_make_block(A, v), 'big')
        for i in range(0, len(I), v):
            x = (int.from_bytes(I[i:i+v], 'big') + B + 1) % (1 << v*8)
            I[i:i+v] = x.to_bytes(v, 'big')

        key += A

    return key[:key_size]


def _pbes1(params: object, passphrase: BytesOrStr, hash_alg: HashType,
           cipher_name: str) -> _Cipher:
    ''








    if (not isinstance(params, tuple) or len(params) != 2 or
            not isinstance(params[0], bytes) or
            not isinstance(params[1], int)):
        raise KeyEncryptionError('Invalid PBES1 encryption parameters')

    salt, count = params

    key_size, iv_size, block_size = get_cipher_params(cipher_name)
    key = _pbkdf1(hash_alg, passphrase, salt, count, key_size + iv_size)
    key, iv = key[:key_size], key[key_size:]

    return _RFC1423Pad(cipher_name, block_size, key, iv)


def _pbe_p12(params: object, passphrase: BytesOrStr, hash_alg: HashType,
             cipher_name: str) -> _Cipher:
    ''








    if (not isinstance(params, tuple) or len(params) != 2 or
            not isinstance(params[0], bytes) or not params[0] or
            not isinstance(params[1], int) or params[1] == 0):
        raise KeyEncryptionError('Invalid PBES1 PKCS#12 encryption parameters')

    salt, count = params

    key_size, iv_size, block_size = get_cipher_params(cipher_name)
    key = _pbkdf_p12(hash_alg, passphrase, salt, count, key_size, 1)

    if block_size == 1:
        cipher: _Cipher = BasicCipher(cipher_name, key, b'')
    else:
        iv = _pbkdf_p12(hash_alg, passphrase, salt, count, iv_size, 2)
        cipher = _RFC1423Pad(cipher_name, block_size, key, iv)

    return cipher


def _pbes2_iv(enc_params: Sequence, cipher_name: str, key: bytes) -> _Cipher:
    ''







    _, iv_size, block_size = get_cipher_params(cipher_name)

    if len(enc_params) != 1 or not isinstance(enc_params[0], bytes):
        raise KeyEncryptionError('Invalid PBES2 encryption parameters')

    if len(enc_params[0]) != iv_size:
        raise KeyEncryptionError('Invalid length IV for PBES2 encryption')

    return _RFC1423Pad(cipher_name, block_size, key, enc_params[0])


def _pbes2_pbkdf2(kdf_params: Sequence, passphrase: BytesOrStr,
                  default_key_size: int) -> bytes:
    ''






    if (len(kdf_params) != 1 or not isinstance(kdf_params[0], tuple) or
            len(kdf_params[0]) < 2):
        raise KeyEncryptionError('Invalid PBES2 key derivation parameters')

    kdf_params = list(kdf_params[0])

    if (not isinstance(kdf_params[0], bytes) or
            not isinstance(kdf_params[1], int)):
        raise KeyEncryptionError('Invalid PBES2 key derivation parameters')

    salt = kdf_params.pop(0)
    count = kdf_params.pop(0)

    if kdf_params and isinstance(kdf_params[0], int):
        key_size = kdf_params.pop(0)    # pragma: no cover, used only by RC2
    else:
        key_size = default_key_size

    if kdf_params:
        if (isinstance(kdf_params[0], tuple) and len(kdf_params[0]) == 2 and
                isinstance(kdf_params[0][0], ObjectIdentifier)):
            prf_alg = kdf_params[0][0]
            if prf_alg in _pbes2_prf:
                hash_name = _pbes2_prf[prf_alg]
            else:
                raise KeyEncryptionError('Unknown PBES2 pseudo-random '
                                         'function')
        else:
            raise KeyEncryptionError('Invalid PBES2 pseudo-random function '
                                     'parameters')
    else:
        hash_name = 'sha1'

    if isinstance(passphrase, str):
        passphrase = passphrase.encode('utf-8')

    return pbkdf2_hmac(hash_name, passphrase, salt, count, key_size)


def _pbes2(params: object, passphrase: BytesOrStr) -> _Cipher:
    ''








    if (not isinstance(params, tuple) or len(params) != 2 or
            not isinstance(params[0], tuple) or len(params[0]) < 1 or
            not isinstance(params[1], tuple) or len(params[1]) < 1):
        raise KeyEncryptionError('Invalid PBES2 encryption parameters')

    kdf_params = list(params[0])

    kdf_alg = kdf_params.pop(0)
    if kdf_alg not in _pbes2_kdf:
        raise KeyEncryptionError('Unknown PBES2 key derivation function')

    enc_params = list(params[1])

    enc_alg = enc_params.pop(0)
    if enc_alg not in _pbes2_cipher:
        raise KeyEncryptionError('Unknown PBES2 encryption algorithm')

    kdf_handler, kdf_args = _pbes2_kdf[kdf_alg]
    enc_handler, cipher_name = _pbes2_cipher[enc_alg]
    default_key_size, _, _ = get_cipher_params(cipher_name)

    key = kdf_handler(kdf_params, passphrase, default_key_size, *kdf_args)
    return enc_handler(enc_params, cipher_name, key)


def register_pkcs1_cipher(pkcs1_cipher_name: str, pkcs1_dek_name: bytes,
                          cipher_name: str) -> None:
    ''

    _pkcs1_cipher[pkcs1_dek_name] = cipher_name
    _pkcs1_dek_name[pkcs1_cipher_name] = pkcs1_dek_name


def register_pkcs8_cipher(pkcs8_cipher_name: str, hash_name: str,
                          pkcs8_cipher_oid: ObjectIdentifier,
                          handler: _PKCS8CipherHandler, hash_alg: HashType,
                          cipher_name: str) -> None:
    ''

    _pkcs8_handler[pkcs8_cipher_oid] = (handler, hash_alg, cipher_name)
    _pkcs8_cipher_oid[pkcs8_cipher_name, hash_name] = pkcs8_cipher_oid


def register_pbes2_cipher(pbes2_cipher_name: str,
                          pbes2_cipher_oid: ObjectIdentifier,
                          handler: _PBES2CipherHandler,
                          cipher_name: str) -> None:
    ''

    _pbes2_cipher[pbes2_cipher_oid] = (handler, cipher_name)
    _pbes2_cipher_oid[pbes2_cipher_name] = pbes2_cipher_oid


def register_pbes2_kdf(kdf_name: str, kdf_oid: ObjectIdentifier,
                       handler: _PBES2KDFHandler, *args: object) -> None:
    ''

    _pbes2_kdf[kdf_oid] = (handler, args)
    _pbes2_kdf_oid[kdf_name] = kdf_oid


def register_pbes2_prf(hash_name: str, prf_oid: ObjectIdentifier) -> None:
    ''

    _pbes2_prf[prf_oid] = hash_name
    _pbes2_prf_oid[hash_name] = prf_oid


def pkcs1_encrypt(data: bytes, pkcs1_cipher_name: str,
                  passphrase: BytesOrStr) -> Tuple[bytes, bytes, bytes]:
    ''








    if pkcs1_cipher_name in _pkcs1_dek_name:
        pkcs1_dek_name = _pkcs1_dek_name[pkcs1_cipher_name]
        cipher_name = _pkcs1_cipher[pkcs1_dek_name]
        key_size, iv_size, block_size = get_cipher_params(cipher_name)

        iv = os.urandom(iv_size)
        key = _pbkdf1(md5, passphrase, iv[:8], 1, key_size)

        cipher = _RFC1423Pad(cipher_name, block_size, key, iv)
        return pkcs1_dek_name, iv, cipher.encrypt(data)
    else:
        raise KeyEncryptionError('Unknown PKCS#1 encryption algorithm')


def pkcs1_decrypt(data: bytes, pkcs1_dek_name: bytes, iv: bytes,
                  passphrase: BytesOrStr) -> bytes:
    ''







    if pkcs1_dek_name in _pkcs1_cipher:
        cipher_name = _pkcs1_cipher[pkcs1_dek_name]
        key_size, _, block_size = get_cipher_params(cipher_name)
        key = _pbkdf1(md5, passphrase, iv[:8], 1, key_size)

        cipher = _RFC1423Pad(cipher_name, block_size, key, iv)
        return cipher.decrypt(data)
    else:
        raise KeyEncryptionError('Unknown PKCS#1 encryption algorithm')


def pkcs8_encrypt(data: bytes, pkcs8_cipher_name: str, hash_name: str,
                  version: int, passphrase: BytesOrStr) -> bytes:
    ''



















    if version == 1 and (pkcs8_cipher_name, hash_name) in _pkcs8_cipher_oid:
        pkcs8_cipher_oid = _pkcs8_cipher_oid[pkcs8_cipher_name, hash_name]
        handler, hash_alg, cipher_name = _pkcs8_handler[pkcs8_cipher_oid]

        alg = pkcs8_cipher_oid
        params: object = (os.urandom(8), 2048)
        cipher = handler(params, passphrase, hash_alg, cipher_name)
    elif version == 2 and pkcs8_cipher_name in _pbes2_cipher_oid:
        pbes2_cipher_oid = _pbes2_cipher_oid[pkcs8_cipher_name]
        _, cipher_name = _pbes2_cipher[pbes2_cipher_oid]
        _, iv_size, _ = get_cipher_params(cipher_name)

        kdf_params = [os.urandom(8), 2048]
        iv = os.urandom(iv_size)
        enc_params = (pbes2_cipher_oid, iv)

        if hash_name != 'sha1':
            if hash_name in _pbes2_prf_oid:
                kdf_params.append((_pbes2_prf_oid[hash_name], None))
            else:
                raise KeyEncryptionError('Unknown PBES2 hash function')

        alg = _ES2
        params = ((_ES2_PBKDF2, tuple(kdf_params)), enc_params)
        cipher = _pbes2(params, passphrase)
    else:
        raise KeyEncryptionError('Unknown PKCS#8 encryption algorithm')

    return der_encode(((alg, params), cipher.encrypt(data)))


def pkcs8_decrypt(key_data: object, passphrase: BytesOrStr) -> object:
    ''






    if not isinstance(key_data, tuple) or len(key_data) != 2:
        raise KeyEncryptionError('Invalid PKCS#8 encrypted key format')

    alg_params, data = key_data

    if (not isinstance(alg_params, tuple) or len(alg_params) != 2 or
            not isinstance(data, bytes)):
        raise KeyEncryptionError('Invalid PKCS#8 encrypted key format')

    alg, params = alg_params

    if alg == _ES2:
        cipher = _pbes2(params, passphrase)
    elif alg in _pkcs8_handler:
        handler, hash_alg, cipher_name = _pkcs8_handler[alg]
        cipher = handler(params, passphrase, hash_alg, cipher_name)
    else:
        raise KeyEncryptionError('Unknown PKCS#8 encryption algorithm')

    try:
        return der_decode(cipher.decrypt(data))
    except (ASN1DecodeError, UnicodeDecodeError):
        raise KeyEncryptionError('Invalid PKCS#8 encrypted key data') from None


_pkcs1_cipher_list = (
    ('aes128-cbc', b'AES-128-CBC',  'aes128-cbc'),
    ('aes192-cbc', b'AES-192-CBC',  'aes192-cbc'),
    ('aes256-cbc', b'AES-256-CBC',  'aes256-cbc'),
    ('des-cbc',    b'DES-CBC',      'des-cbc'),
    ('des3-cbc',   b'DES-EDE3-CBC', 'des3-cbc')
)

_pkcs8_cipher_list = (
    ('des-cbc', 'md5',  _ES1_MD5_DES,  _pbes1,   md5,  'des-cbc'),
    ('des-cbc', 'sha1', _ES1_SHA1_DES, _pbes1,   sha1, 'des-cbc'),

    ('des2-cbc','sha1', _P12_DES2,     _pbe_p12, sha1, 'des2-cbc'),
    ('des3-cbc','sha1', _P12_DES3,     _pbe_p12, sha1, 'des3-cbc'),
    ('rc4-40',  'sha1', _P12_RC4_40,   _pbe_p12, sha1, 'arcfour40'),
    ('rc4-128', 'sha1', _P12_RC4_128,  _pbe_p12, sha1, 'arcfour')
)

_pbes2_cipher_list = (
    ('aes128-cbc',   _ES2_AES128,  _pbes2_iv,  'aes128-cbc'),
    ('aes192-cbc',   _ES2_AES192,  _pbes2_iv,  'aes192-cbc'),
    ('aes256-cbc',   _ES2_AES256,  _pbes2_iv,  'aes256-cbc'),
    ('blowfish-cbc', _ES2_BF,      _pbes2_iv,  'blowfish-cbc'),
    ('cast128-cbc',  _ES2_CAST128, _pbes2_iv,  'cast128-cbc'),
    ('des-cbc',      _ES2_DES,     _pbes2_iv,  'des-cbc'),
    ('des3-cbc',     _ES2_DES3,    _pbes2_iv,  'des3-cbc')
)

_pbes2_kdf_list = (
    ('pbkdf2', _ES2_PBKDF2, _pbes2_pbkdf2),
)

_pbes2_prf_list = (
    ('sha1',   _ES2_SHA1),
    ('sha224', _ES2_SHA224),
    ('sha256', _ES2_SHA256),
    ('sha384', _ES2_SHA384),
    ('sha512', _ES2_SHA512)
)

for _pkcs1_cipher_args in _pkcs1_cipher_list:
    register_pkcs1_cipher(*_pkcs1_cipher_args)

for _pkcs8_cipher_args in _pkcs8_cipher_list:
    register_pkcs8_cipher(*_pkcs8_cipher_args)

for _pbes2_cipher_args in _pbes2_cipher_list:
    register_pbes2_cipher(*_pbes2_cipher_args)

for _pbes2_kdf_args in _pbes2_kdf_list:
    register_pbes2_kdf(*_pbes2_kdf_args)

for _pbes2_prf_args in _pbes2_prf_list:
    register_pbes2_prf(*_pbes2_prf_args)
