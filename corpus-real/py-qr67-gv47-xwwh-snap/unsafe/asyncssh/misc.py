



















''

import asyncio
import fnmatch
import functools
import ipaddress
import os
import re
import shlex
import socket
import sys

from pathlib import Path, PurePath
from random import SystemRandom
from types import TracebackType
from typing import Any, AsyncContextManager, Awaitable, Callable, Dict
from typing import Generator, Generic, IO, Iterator, Mapping, Optional
from typing import Sequence, Tuple, Type, TypeVar, Union, cast, overload
from typing_extensions import Literal, Protocol

from .constants import DEFAULT_LANG
from .constants import DISC_COMPRESSION_ERROR, DISC_CONNECTION_LOST
from .constants import DISC_HOST_KEY_NOT_VERIFIABLE, DISC_ILLEGAL_USER_NAME
from .constants import DISC_KEY_EXCHANGE_FAILED, DISC_MAC_ERROR
from .constants import DISC_NO_MORE_AUTH_METHODS_AVAILABLE
from .constants import DISC_PROTOCOL_ERROR, DISC_PROTOCOL_VERSION_NOT_SUPPORTED
from .constants import DISC_SERVICE_NOT_AVAILABLE

_pywin32_available = False

if sys.platform == 'win32': # pragma: no cover
    try:
        import msvcrt
        import win32file
        import winioctlcon
        _pywin32_available = True
    except ImportError:
        pass

if sys.platform != 'win32': # pragma: no branch
    import fcntl
    import struct
    import termios

TermModes = Mapping[int, int]
TermModesArg = Optional[TermModes]
TermSize = Tuple[int, int, int, int]
TermSizeArg = Union[None, Tuple[int, int], TermSize]


class _Hash(Protocol):
    ''

    @property
    def digest_size(self) -> int:
        ''

    @property
    def block_size(self) -> int:
        ''

    @property
    def name(self) -> str:
        ''

    def digest(self) -> bytes:
        ''

    def hexdigest(self) -> str:
        ''

    def update(self, __data: bytes) -> None:
        ''


class HashType(Protocol):
    ''

    def __call__(self, __data: bytes = ...) -> _Hash:
        ''


class _SupportsWaitClosed(Protocol):
    ''

    async def wait_closed(self) -> None:
        ''


_T = TypeVar('_T')
DefTuple = Union[Tuple[()], _T]
MaybeAwait = Union[_T, Awaitable[_T]]

ExcInfo = Tuple[Type[BaseException], BaseException, TracebackType]
OptExcInfo = Union[ExcInfo, Tuple[None, None, None]]

BytesOrStr = Union[bytes, str]
BytesOrStrDict = Dict[BytesOrStr, BytesOrStr]
FilePath = Union[str, PurePath]
HostPort = Tuple[str, int]
IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
SockAddr = Union[Tuple[str, int], Tuple[str, int, int, int]]

EnvMap = Mapping[BytesOrStr, BytesOrStr]
EnvItems = Sequence[Tuple[BytesOrStr, BytesOrStr]]
EnvSeq = Sequence[BytesOrStr]
Env = Union[EnvMap, EnvItems, EnvSeq]



_random = SystemRandom()
randrange = _random.randrange

_unit_pattern = re.compile(r'([A-Za-z])')
_byte_units = {'': 1, 'k': 1024, 'm': 1024*1024, 'g': 1024*1024*1024}
_time_units = {'': 1, 's': 1, 'm': 60, 'h': 60*60,
               'd': 24*60*60, 'w': 7*24*60*60}


def encode_env(env: Env) -> Iterator[Tuple[bytes, bytes]]:
    ''

    if hasattr(env, 'items'):
        env = cast(Env, env.items())

    try:
        for item in env:
            if isinstance(item, (bytes, str)):
                if isinstance(item, str):
                    item = item.encode('utf-8')

                key_bytes, value_bytes = item.split(b'=', 1)
            else:
                key, value = item

                key_bytes = key.encode('utf-8') \
                    if isinstance(key, str) else key

                value_bytes = value.encode('utf-8') \
                    if isinstance(value, str) else value

            yield key_bytes, value_bytes
    except (TypeError, ValueError) as exc:
        raise ValueError(f'Invalid environment value: {exc}') from None


def lookup_env(patterns: EnvSeq) -> Iterator[Tuple[bytes, bytes]]:
    ''

    for pattern in patterns:
        if isinstance(pattern, str):
            pattern = pattern.encode('utf-8')

        if os.supports_bytes_environ:
            for key_bytes, value_bytes in os.environb.items():
                if fnmatch.fnmatch(key_bytes, pattern):
                    yield key_bytes, value_bytes
        else: # pragma: no cover
            for key, value in os.environ.items():
                key_bytes = key.encode('utf-8')
                value_bytes = value.encode('utf-8')
                if fnmatch.fnmatch(key_bytes, pattern):
                    yield key_bytes, value_bytes


def decode_env(env: Dict[bytes, bytes]) -> Iterator[Tuple[str, str]]:
    ''

    for key, value in env.items():
        try:
            yield key.decode('utf-8'), value.decode('utf-8')
        except UnicodeDecodeError:
            pass


def hide_empty(value: object, prefix: str = ', ') -> str:
    ''

    value = str(value)
    return prefix + value if value else ''


def plural(length: int, label: str, suffix: str = 's') -> str:
    ''

    return f'{length} {label}{suffix if length != 1 else ""}'


def all_ints(seq: Sequence[object]) -> bool:
    ''

    return all(isinstance(i, int) for i in seq)


def get_symbol_names(symbols: Mapping[str, int], prefix: str,
                     strip_leading: int = 0) -> Mapping[int, str]:
    ''

    return {value: name[strip_leading:] for name, value in symbols.items()
            if name.startswith(prefix)}



_HANDLER_PUNCTUATION = (('@', '_at_'), ('.', '_dot_'), ('-', '_'))

def map_handler_name(name: str) -> str:
    ''

    for old, new in _HANDLER_PUNCTUATION:
        name = name.replace(old, new)

    return name


def _normalize_scoped_ip(addr: str) -> str:
    ''







    try:
        addrinfo = socket.getaddrinfo(addr, None, family=socket.AF_UNSPEC,
                                      type=socket.SOCK_STREAM,
                                      flags=socket.AI_NUMERICHOST)[0]
    except socket.gaierror:
        return addr

    if addrinfo[0] == socket.AF_INET6:
        sa = addrinfo[4]
        addr = cast(str, sa[0])

        idx = addr.find('%')
        if idx >= 0: # pragma: no cover
            addr = addr[:idx]

        ip = ipaddress.ip_address(addr)

        if ip.is_link_local:
            scope_id = cast(Tuple[str, int, int, int], sa)[3]
            addr = str(ipaddress.ip_address(int(ip) | (scope_id << 96)))

    return addr


def ip_address(addr: str) -> IPAddress:
    ''

    return ipaddress.ip_address(_normalize_scoped_ip(addr))


def ip_network(addr: str) -> IPNetwork:
    ''

    idx = addr.find('/')
    if idx >= 0:
        addr, mask = addr[:idx], addr[idx:]
    else:
        mask = ''

    return ipaddress.ip_network(_normalize_scoped_ip(addr) + mask)


def open_file(filename: FilePath, mode: str, buffering: int = -1) -> IO[bytes]:
    ''

    return open(Path(filename).expanduser(), mode, buffering=buffering)


@overload
def read_file(filename: FilePath) -> bytes:
    ''

@overload
def read_file(filename: FilePath, mode: Literal['rb']) -> bytes:
    ''

@overload
def read_file(filename: FilePath, mode: Literal['r']) -> str:
    ''

def read_file(filename, mode = 'rb'):
    ''

    with open_file(filename, mode) as f:
        return f.read()


def write_file(filename: FilePath, data: bytes, mode: str = 'wb') -> int:
    ''

    with open_file(filename, mode) as f:
        return f.write(data)


if sys.platform == 'win32' and _pywin32_available: # pragma: no cover
    def make_sparse_file(file_obj: IO) -> None:
        ''

        handle = msvcrt.get_osfhandle(file_obj.fileno())

        win32file.DeviceIoControl(handle, winioctlcon.FSCTL_SET_SPARSE,
                                  b'', 0, None)
else:
    def make_sparse_file(_file_obj: IO) -> None:
        ''


def _parse_units(value: str, suffixes: Mapping[str, int], label: str) -> float:
    ''

    matches = _unit_pattern.split(value)

    if matches[-1]:
        matches.append('')
    else:
        matches.pop()

    try:
        return sum(float(matches[i]) * suffixes[matches[i+1].lower()]
                   for i in range(0, len(matches), 2))
    except KeyError:
        raise ValueError('Invalid ' + label) from None


def parse_byte_count(value: str) -> int:
    ''

    return int(_parse_units(value, _byte_units, 'byte count'))


def parse_time_interval(value: str) -> float:
    ''

    return _parse_units(value, _time_units, 'time interval')


def split_args(command: str) -> Sequence[str]:
    ''

    lex = shlex.shlex(command, posix=True)
    lex.whitespace_split = True

    if sys.platform == 'win32': # pragma: no cover
        lex.escape = []

    return list(lex)


_ACM = TypeVar('_ACM', bound=AsyncContextManager, covariant=True)

class _ACMWrapper(Generic[_ACM]):
    ''

    def __init__(self, coro: Awaitable[_ACM]):
        self._coro = coro
        self._coro_result: Optional[_ACM] = None

    def __await__(self) -> Generator[Any, None, _ACM]:
        return self._coro.__await__()

    async def __aenter__(self) -> _ACM:
        self._coro_result = await self._coro

        return await self._coro_result.__aenter__()

    async def __aexit__(self, exc_type: Optional[Type[BaseException]],
                        exc_value: Optional[BaseException],
                        traceback: Optional[TracebackType]) -> Optional[bool]:
        assert self._coro_result is not None

        exit_result = await self._coro_result.__aexit__(
            exc_type, exc_value, traceback)

        self._coro_result = None

        return exit_result


_ACMCoro = Callable[..., Awaitable[_ACM]]
_ACMWrapperFunc = Callable[..., _ACMWrapper[_ACM]]

def async_context_manager(coro: _ACMCoro[_ACM]) -> _ACMWrapperFunc[_ACM]:
    ''











    @functools.wraps(coro)
    def context_wrapper(*args, **kwargs) -> _ACMWrapper[_ACM]:
        ''

        return _ACMWrapper(coro(*args, **kwargs))

    return context_wrapper


async def maybe_wait_closed(writer: '_SupportsWaitClosed') -> None:
    ''










    try:
        await writer.wait_closed()
    except AttributeError: # pragma: no cover
        pass


async def run_in_executor(func: Callable[..., _T], *args: object) -> _T:
    ''

    loop = asyncio.get_event_loop()

    return await loop.run_in_executor(None, func, *args)


def set_terminal_size(tty: IO, width: int, height: int,
                      pixwidth: int, pixheight: int) -> None:
    ''

    fcntl.ioctl(tty, termios.TIOCSWINSZ,
                struct.pack('hhhh', height, width, pixwidth, pixheight))


class Options:
    ''

    kwargs: Dict[str, object]

    def __init__(self, options: Optional['Options'] = None, **kwargs: object):
        if options:
            if not isinstance(options, type(self)):
                raise TypeError(f'Invalid {type(self).__name__}, '
                                f'got {type(options).__name__}')

            self.kwargs = options.kwargs.copy()
        else:
            self.kwargs = {}

        self.kwargs.update(kwargs)
        self.prepare(**self.kwargs)

    def prepare(self, **kwargs: object) -> None:
        ''

    def update(self, **kwargs: object) -> None:
        ''

        self.kwargs.update(kwargs)
        self.prepare(**self.kwargs)


class _RecordMeta(type):
    ''

    __slots__: Dict[str, object] = {}

    def __new__(mcs: Type['_RecordMeta'], name: str, bases: Tuple[type, ...],
                ns: Dict[str, object]) -> '_RecordMeta':
        cls = cast(_RecordMeta, super().__new__(mcs, name, bases, ns))

        if name != 'Record':
            fields = cast(Mapping[str, str], cls.__annotations__.keys())
            defaults = {k: ns.get(k) for k in fields}
            cls.__slots__ = defaults

        return cls


class Record(metaclass=_RecordMeta):
    ''

    __slots__: Mapping[str, object] = {}

    def __init__(self, *args: object, **kwargs: object):
        for k, v in self.__slots__.items():
            setattr(self, k, v)

        for k, v in zip(self.__slots__, args):
            setattr(self, k, v)

        for k, v in kwargs.items():
            setattr(self, k, v)

    def __repr__(self) -> str:
        values = ', '.join(f'{k}={getattr(self, k)!r}' for k in self.__slots__)

        return f'{type(self).__name__}({values})'

    def __str__(self) -> str:
        values = ((k, self._format(k, getattr(self, k)))
                  for k in self.__slots__)

        return ', '.join(f'{k}: {v}' for k, v in values if v is not None)

    def _format(self, k: str, v: object) -> Optional[str]:
        ''

        # pylint: disable=no-self-use,unused-argument

        return str(v)

class Error(Exception):
    ''

    def __init__(self, code: int, reason: str, lang: str = DEFAULT_LANG):
        super().__init__(reason)
        self.code = code
        self.reason = reason
        self.lang = lang


class DisconnectError(Error):
    ''





















class CompressionError(DisconnectError):
    ''













    def __init__(self, reason: str, lang: str = DEFAULT_LANG):
        super().__init__(DISC_COMPRESSION_ERROR, reason, lang)


class ConnectionLost(DisconnectError):
    ''















    def __init__(self, reason: str, lang: str = DEFAULT_LANG):
        super().__init__(DISC_CONNECTION_LOST, reason, lang)


class HostKeyNotVerifiable(DisconnectError):
    ''













    def __init__(self, reason: str, lang: str = DEFAULT_LANG):
        super().__init__(DISC_HOST_KEY_NOT_VERIFIABLE, reason, lang)


class IllegalUserName(DisconnectError):
    ''













    def __init__(self, reason: str, lang: str = DEFAULT_LANG):
        super().__init__(DISC_ILLEGAL_USER_NAME, reason, lang)


class KeyExchangeFailed(DisconnectError):
    ''












    def __init__(self, reason: str, lang: str = DEFAULT_LANG):
        super().__init__(DISC_KEY_EXCHANGE_FAILED, reason, lang)


class MACError(DisconnectError):
    ''














    def __init__(self, reason: str, lang: str = DEFAULT_LANG):
        super().__init__(DISC_MAC_ERROR, reason, lang)


class PermissionDenied(DisconnectError):
    ''













    def __init__(self, reason: str, lang: str = DEFAULT_LANG):
        super().__init__(DISC_NO_MORE_AUTH_METHODS_AVAILABLE, reason, lang)


class ProtocolError(DisconnectError):
    ''













    def __init__(self, reason: str, lang: str = DEFAULT_LANG):
        super().__init__(DISC_PROTOCOL_ERROR, reason, lang)


class ProtocolNotSupported(DisconnectError):
    ''













    def __init__(self, reason: str, lang: str = DEFAULT_LANG):
        super().__init__(DISC_PROTOCOL_ERROR, reason, lang)


class ServiceNotAvailable(DisconnectError):
    ''













    def __init__(self, reason: str, lang: str = DEFAULT_LANG):
        super().__init__(DISC_SERVICE_NOT_AVAILABLE, reason, lang)


class ChannelOpenError(Error):
    ''


















class ChannelListenError(Exception):
    ''











class PasswordChangeRequired(Exception):
    ''















    def __init__(self, prompt: str, lang: str = DEFAULT_LANG):
        super().__init__(f'Password change required: {prompt}')
        self.prompt = prompt
        self.lang = lang


class BreakReceived(Exception):
    ''










    def __init__(self, msec: int):
        super().__init__(f'Break for {msec} msec')
        self.msec = msec


class SignalReceived(Exception):
    ''










    def __init__(self, signal: str):
        super().__init__(f'Signal: {signal}')
        self.signal = signal


class SoftEOFReceived(Exception):
    ''






    def __init__(self) -> None:
        super().__init__('Soft EOF')


class TerminalSizeChanged(Exception):
    ''



















    def __init__(self, width: int, height: int, pixwidth: int, pixheight: int):
        super().__init__(f'Terminal size change: ({width}, {height}, '
                         f'{pixwidth}, {pixheight})')
        self.width = width
        self.height = height
        self.pixwidth = pixwidth
        self.pixheight = pixheight

    @property
    def term_size(self) -> TermSize:
        ''

        return self.width, self.height, self.pixwidth, self.pixheight


_disc_error_map = {
    DISC_PROTOCOL_ERROR: ProtocolError,
    DISC_KEY_EXCHANGE_FAILED: KeyExchangeFailed,
    DISC_MAC_ERROR: MACError,
    DISC_COMPRESSION_ERROR: CompressionError,
    DISC_SERVICE_NOT_AVAILABLE: ServiceNotAvailable,
    DISC_PROTOCOL_VERSION_NOT_SUPPORTED: ProtocolNotSupported,
    DISC_HOST_KEY_NOT_VERIFIABLE: HostKeyNotVerifiable,
    DISC_CONNECTION_LOST: ConnectionLost,
    DISC_NO_MORE_AUTH_METHODS_AVAILABLE: PermissionDenied,
    DISC_ILLEGAL_USER_NAME: IllegalUserName
}


def construct_disc_error(code: int, reason: str, lang: str) -> DisconnectError:
    ''

    try:
        return _disc_error_map[code](reason, lang)
    except KeyError:
        return DisconnectError(code, f'{reason} (error {code})', lang)
