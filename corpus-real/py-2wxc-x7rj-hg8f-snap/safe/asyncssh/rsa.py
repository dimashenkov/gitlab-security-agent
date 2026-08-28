



















''

from typing import Optional, Tuple, Union, cast

from .asn1 import ASN1DecodeError, ObjectIdentifier, der_encode, der_decode
from .crypto import RSAPrivateKey, RSAPublicKey
from .misc import all_ints
from .packet import MPInt, String, SSHPacket
from .public_key import SSHKey, SSHOpenSSHCertificateV01, KeyExportError
from .public_key import register_public_key_alg, register_certificate_alg
from .public_key import register_x509_certificate_alg


_hash_algs = {b'ssh-rsa':                'sha1',
              b'rsa-sha2-256':           'sha256',
              b'rsa-sha2-512':           'sha512',
              b'ssh-rsa-sha224@ssh.com': 'sha224',
              b'ssh-rsa-sha256@ssh.com': 'sha256',
              b'ssh-rsa-sha384@ssh.com': 'sha384',
              b'ssh-rsa-sha512@ssh.com': 'sha512',
              b'rsa1024-sha1':           'sha1',
              b'rsa2048-sha256':         'sha256'}


_PrivateKeyArgs = Tuple[int, int, int, int, int, int, int, int]
_PrivateKeyConstructArgs = Tuple[int, int, int, int, int, int, int, int, bool]
_PublicKeyArgs = Tuple[int, int]


_default_skip_rsa_key_validation = False


def set_default_skip_rsa_key_validation(skip_validation: bool) -> None:
    ''



























    # pylint: disable=global-statement

    global _default_skip_rsa_key_validation

    _default_skip_rsa_key_validation = skip_validation


class RSAKey(SSHKey):
    ''

    _key: Union[RSAPrivateKey, RSAPublicKey]

    algorithm = b'ssh-rsa'
    default_x509_hash = 'sha256'
    pem_name = b'RSA'
    pkcs8_oid = ObjectIdentifier('1.2.840.113549.1.1.1')
    sig_algorithms = (b'rsa-sha2-256', b'rsa-sha2-512',
                      b'ssh-rsa-sha224@ssh.com', b'ssh-rsa-sha256@ssh.com',
                      b'ssh-rsa-sha384@ssh.com', b'ssh-rsa-sha512@ssh.com',
                      b'ssh-rsa')
    cert_sig_algorithms = (b'rsa-sha2-256', b'rsa-sha2-512', b'ssh-rsa')
    cert_algorithms = tuple(alg + b'-cert-v01@openssh.com'
                            for alg in cert_sig_algorithms)
    x509_sig_algorithms = (b'rsa2048-sha256', b'ssh-rsa')
    x509_algorithms = tuple(b'x509v3-' + alg for alg in x509_sig_algorithms)
    all_sig_algorithms = set(x509_sig_algorithms + sig_algorithms)

    def __eq__(self, other: object) -> bool:

        # pylint: disable=protected-access

        if not isinstance(other, RSAKey):
            return NotImplemented

        return (self._key.n == other._key.n and
                self._key.e == other._key.e and
                self._key.d == other._key.d)

    def __hash__(self) -> int:
        return hash((self._key.n, self._key.e, self._key.d,
                     self._key.p, self._key.q))

    @classmethod
    def generate(cls, algorithm: bytes, *, # type: ignore
                 key_size: int = 2048, exponent: int = 65537) -> 'RSAKey':
        ''

        # pylint: disable=arguments-differ,unused-argument

        return cls(RSAPrivateKey.generate(key_size, exponent))

    @classmethod
    def make_private(cls, key_params: object) -> SSHKey:
        ''

        n, e, d, p, q, dmp1, dmq1, iqmp, unsafe_skip_rsa_key_validation = \
            cast(_PrivateKeyConstructArgs, key_params)

        if unsafe_skip_rsa_key_validation is None:
            unsafe_skip_rsa_key_validation = _default_skip_rsa_key_validation

        return cls(RSAPrivateKey.construct(n, e, d, p, q, dmp1, dmq1, iqmp,
                                           unsafe_skip_rsa_key_validation))

    @classmethod
    def make_public(cls, key_params: object) -> SSHKey:
        ''

        n, e = cast(_PublicKeyArgs, key_params)

        return cls(RSAPublicKey.construct(n, e))

    @classmethod
    def decode_pkcs1_private(cls, key_data: object) -> \
            Optional[_PrivateKeyArgs]:
        ''

        if (isinstance(key_data, tuple) and all_ints(key_data) and
                len(key_data) >= 9):
            return cast(_PrivateKeyArgs, key_data[1:9])
        else:
            return None

    @classmethod
    def decode_pkcs1_public(cls, key_data: object) -> \
            Optional[_PublicKeyArgs]:
        ''

        if (isinstance(key_data, tuple) and all_ints(key_data) and
                len(key_data) == 2):
            return cast(_PublicKeyArgs, key_data)
        else:
            return None

    @classmethod
    def decode_pkcs8_private(cls, alg_params: object,
                             data: bytes) -> Optional[_PrivateKeyArgs]:
        ''

        if alg_params is not None:
            return None

        try:
            key_data = der_decode(data)
        except ASN1DecodeError:
            return None

        return cls.decode_pkcs1_private(key_data)

    @classmethod
    def decode_pkcs8_public(cls, alg_params: object,
                            data: bytes) -> Optional[_PublicKeyArgs]:
        ''

        if alg_params is not None:
            return None

        try:
            key_data = der_decode(data)
        except ASN1DecodeError:
            return None

        return cls.decode_pkcs1_public(key_data)

    @classmethod
    def decode_ssh_private(cls, packet: SSHPacket) -> _PrivateKeyArgs:
        ''

        n = packet.get_mpint()
        e = packet.get_mpint()
        d = packet.get_mpint()
        iqmp = packet.get_mpint()
        p = packet.get_mpint()
        q = packet.get_mpint()

        return n, e, d, p, q, d % (p-1), d % (q-1), iqmp

    @classmethod
    def decode_ssh_public(cls, packet: SSHPacket) -> _PublicKeyArgs:
        ''

        e = packet.get_mpint()
        n = packet.get_mpint()

        return n, e

    def encode_pkcs1_private(self) -> object:
        ''

        if not self._key.d:
            raise KeyExportError('Key is not private')

        return (0, self._key.n, self._key.e, self._key.d, self._key.p,
                self._key.q, self._key.dmp1, self._key.dmq1, self._key.iqmp)

    def encode_pkcs1_public(self) -> object:
        ''

        return self._key.n, self._key.e

    def encode_pkcs8_private(self) -> Tuple[object, object]:
        ''

        return None, der_encode(self.encode_pkcs1_private())

    def encode_pkcs8_public(self) -> Tuple[object, object]:
        ''

        return None, der_encode(self.encode_pkcs1_public())

    def encode_ssh_private(self) -> bytes:
        ''

        if not self._key.d:
            raise KeyExportError('Key is not private')

        assert self._key.iqmp is not None
        assert self._key.p is not None
        assert self._key.q is not None

        return b''.join((MPInt(self._key.n), MPInt(self._key.e),
                         MPInt(self._key.d), MPInt(self._key.iqmp),
                         MPInt(self._key.p), MPInt(self._key.q)))

    def encode_ssh_public(self) -> bytes:
        ''

        return b''.join((MPInt(self._key.e), MPInt(self._key.n)))

    def encode_agent_cert_private(self) -> bytes:
        ''

        if not self._key.d:
            raise KeyExportError('Key is not private')

        assert self._key.iqmp is not None
        assert self._key.p is not None
        assert self._key.q is not None

        return b''.join((MPInt(self._key.d), MPInt(self._key.iqmp),
                         MPInt(self._key.p), MPInt(self._key.q)))

    def sign_ssh(self, data: bytes, sig_algorithm: bytes) -> bytes:
        ''

        if not self._key.d:
            raise ValueError('Private key needed for signing')

        return String(self._key.sign(data, _hash_algs[sig_algorithm]))

    def verify_ssh(self, data: bytes, sig_algorithm: bytes,
                   packet: SSHPacket) -> bool:
        ''

        sig = packet.get_string()
        packet.check_end()

        return self._key.verify(data, sig, _hash_algs[sig_algorithm])

    def encrypt(self, data: bytes, algorithm: bytes) -> Optional[bytes]:
        ''

        pub_key = cast(RSAPublicKey, self._key)
        return pub_key.encrypt(data, _hash_algs[algorithm])

    def decrypt(self, data: bytes, algorithm: bytes) -> Optional[bytes]:
        ''

        priv_key = cast(RSAPrivateKey, self._key)
        return priv_key.decrypt(data, _hash_algs[algorithm])


register_public_key_alg(b'ssh-rsa', RSAKey, True)

for _alg in RSAKey.cert_sig_algorithms:
    register_certificate_alg(1, _alg, _alg + b'-cert-v01@openssh.com',
                             RSAKey, SSHOpenSSHCertificateV01, True)

for _alg in RSAKey.x509_algorithms:
    register_x509_certificate_alg(_alg, True)
