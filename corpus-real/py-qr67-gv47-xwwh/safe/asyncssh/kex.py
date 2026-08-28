



















''

import binascii
from hashlib import md5
from typing import TYPE_CHECKING, Dict, List, Sequence, Tuple, Type

from .logging import SSHLogger
from .misc import HashType
from .packet import SSHPacketHandler


if TYPE_CHECKING:
    # pylint: disable=cyclic-import
    from .connection import SSHConnection


_KexAlgList = List[bytes]
_KexAlgMap = Dict[bytes, Tuple[Type['Kex'], HashType, Tuple]]


_kex_algs: _KexAlgList = []
_default_kex_algs:_KexAlgList = []
_kex_handlers: _KexAlgMap = {}

_gss_kex_algs: _KexAlgList = []
_default_gss_kex_algs: _KexAlgList = []
_gss_kex_handlers: _KexAlgMap = {}


class Kex(SSHPacketHandler):
    ''

    def __init__(self, alg: bytes, conn: 'SSHConnection', hash_alg: HashType):
        self.algorithm = alg

        self._conn = conn
        self._logger = conn.logger
        self._hash_alg = hash_alg


    async def start(self) -> None:
        ''

        raise NotImplementedError

    def send_packet(self, pkttype: int, *args: bytes) -> None:
        ''

        self._conn.send_packet(pkttype, *args, handler=self)

    @property
    def logger(self) -> SSHLogger:
        ''

        return self._logger

    def compute_key(self, k: bytes, h: bytes, x: bytes,
                    session_id: bytes, keylen: int) -> bytes:
        ''

        key = b''
        while len(key) < keylen:
            hash_obj = self._hash_alg()
            hash_obj.update(k)
            hash_obj.update(h)
            hash_obj.update(key if key else x + session_id)
            key += hash_obj.digest()

        return key[:keylen]


def register_kex_alg(alg: bytes, handler: Type[Kex], hash_alg: HashType,
                     args: Tuple, default: bool) -> None:
    ''

    _kex_algs.append(alg)

    if default:
        _default_kex_algs.append(alg)

    _kex_handlers[alg] = (handler, hash_alg, args)


def register_gss_kex_alg(alg: bytes, handler: Type[Kex], hash_alg: HashType,
                         args: Tuple, default: bool) -> None:
    ''

    _gss_kex_algs.append(alg)

    if default:
        _default_gss_kex_algs.append(alg)

    _gss_kex_handlers[alg] = (handler, hash_alg, args)


def get_kex_algs() -> List[bytes]:
    ''

    return _gss_kex_algs + _kex_algs


def get_default_kex_algs() -> List[bytes]:
    ''

    return _default_gss_kex_algs + _default_kex_algs


def expand_kex_algs(kex_algs: Sequence[bytes], mechs: Sequence[bytes],
                    host_key_available: bool) -> List[bytes]:
    ''

    expanded_kex_algs: List[bytes] = []

    for alg in kex_algs:
        if alg.startswith(b'gss-'):
            for mech in mechs:
                suffix = b'-' + binascii.b2a_base64(md5(mech).digest())[:-1]
                expanded_kex_algs.append(alg + suffix)
        elif host_key_available:
            expanded_kex_algs.append(alg)

    return expanded_kex_algs


def get_kex(conn: 'SSHConnection', alg: bytes) -> Kex:
    ''






    if alg.startswith(b'gss-'):
        alg = alg.rsplit(b'-', 1)[0]
        handler, hash_alg, args = _gss_kex_handlers[alg]
    else:
        handler, hash_alg, args = _kex_handlers[alg]

    return handler(alg, conn, hash_alg, *args)
