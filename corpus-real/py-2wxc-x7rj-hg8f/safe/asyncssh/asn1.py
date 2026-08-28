



















''













from typing import Dict, FrozenSet, Sequence, Set, Tuple, Type, TypeVar, Union
from typing import cast


_DERClass = Type['DERType']
_DERClassVar = TypeVar('_DERClassVar', bound='_DERClass')



UNIVERSAL         = 0x00
APPLICATION       = 0x01
CONTEXT_SPECIFIC  = 0x02
PRIVATE           = 0x03


END_OF_CONTENT    = 0x00
BOOLEAN           = 0x01
INTEGER           = 0x02
BIT_STRING        = 0x03
OCTET_STRING      = 0x04
NULL              = 0x05
OBJECT_IDENTIFIER = 0x06
UTF8_STRING       = 0x0c
SEQUENCE          = 0x10
SET               = 0x11
IA5_STRING        = 0x16

_asn1_class = ('Universal', 'Application', 'Context-specific', 'Private')

_der_class_by_tag: Dict[int, _DERClass] = {}
_der_class_by_type: Dict[Union[object, _DERClass], _DERClass] = {}


def _encode_identifier(asn1_class: int, constructed: bool, tag: int) -> bytes:
    ''

    if asn1_class not in (UNIVERSAL, APPLICATION, CONTEXT_SPECIFIC, PRIVATE):
        raise ASN1EncodeError('Invalid ASN.1 class')

    flags = (asn1_class << 6) | (0x20 if constructed else 0x00)

    if tag < 0x20:
        identifier = [flags | tag]
    else:
        identifier = [tag & 0x7f]

        while tag >= 0x80:
            tag >>= 7
            identifier.append(0x80 | (tag & 0x7f))

        identifier.append(flags | 0x1f)

    return bytes(identifier[::-1])


class ASN1Error(ValueError):
    ''


class ASN1EncodeError(ASN1Error):
    ''


class ASN1DecodeError(ASN1Error):
    ''


class DERType:
    ''

    identifier: bytes = b''

    @staticmethod
    def encode(value: object) -> bytes:
        ''

        raise NotImplementedError

    @classmethod
    def decode(cls, constructed: bool, content: bytes) -> object:
        ''

        raise NotImplementedError


class DERTag:
    ''














    def __init__(self, tag: int, types: Sequence[object] = (),
                 constructed: bool = False):
        self._tag = tag
        self._types = types
        self._identifier = _encode_identifier(UNIVERSAL, constructed, tag)

    def __call__(self, cls: _DERClassVar) -> _DERClassVar:
        cls.identifier = self._identifier

        _der_class_by_tag[self._tag] = cls

        if self._types:
            for t in self._types:
                _der_class_by_type[t] = cls
        else:
            _der_class_by_type[cls] = cls

        return cls


class RawDERObject:
    ''








    def __init__(self, tag: int, content: bytes, asn1_class: int):
        self.asn1_class = asn1_class
        self.tag = tag
        self.content = content

    def __repr__(self) -> str:
        return f'RawDERObject({_asn1_class[self.asn1_class]}, ' \
               f'{self.tag}, {self.content!r})'

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, RawDERObject): # pragma: no cover
            return NotImplemented

        return (self.asn1_class == other.asn1_class and
                self.tag == other.tag and self.content == other.content)

    def __hash__(self) -> int:
        return hash((self.asn1_class, self.tag, self.content))

    def encode_identifier(self) -> bytes:
        ''

        return _encode_identifier(self.asn1_class, False, self.tag)

    @staticmethod
    def encode(value: object) -> bytes:
        ''

        return cast('RawDERObject', value).content


class TaggedDERObject:
    ''









    def __init__(self, tag: int, value: object,
                 asn1_class: int = CONTEXT_SPECIFIC):
        self.asn1_class = asn1_class
        self.tag = tag
        self.value = value

    def __repr__(self) -> str:
        if self.asn1_class == CONTEXT_SPECIFIC:
            return f'TaggedDERObject({self.tag}, {self.value!r})'
        else:
            return f'TaggedDERObject({_asn1_class[self.asn1_class]}, ' \
                   f'{self.tag}, {self.value!r})'

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TaggedDERObject): # pragma: no cover
            return NotImplemented

        return (self.asn1_class == other.asn1_class and
                self.tag == other.tag and self.value == other.value)

    def __hash__(self) -> int:
        return hash((self.asn1_class, self.tag, self.value))

    def encode_identifier(self) -> bytes:
        ''

        return _encode_identifier(self.asn1_class, True, self.tag)

    @staticmethod
    def encode(value: object) -> bytes:
        ''

        return der_encode(cast('TaggedDERObject', value).value)


@DERTag(NULL, (type(None),))
class _Null(DERType):
    ''

    @staticmethod
    def encode(value: object) -> bytes:
        ''

        # pylint: disable=unused-argument

        return b''

    @classmethod
    def decode(cls, constructed: bool, content: bytes) -> None:
        ''

        if constructed:
            raise ASN1DecodeError('NULL should not be constructed')

        if content:
            raise ASN1DecodeError('NULL should not have associated content')

        return None


@DERTag(BOOLEAN, (bool,))
class _Boolean(DERType):
    ''

    @staticmethod
    def encode(value: object) -> bytes:
        ''

        return b'\xff' if value else b'\0'

    @classmethod
    def decode(cls, constructed: bool, content: bytes) -> bool:
        ''

        if constructed:
            raise ASN1DecodeError('BOOLEAN should not be constructed')

        if content not in {b'\x00', b'\xff'}:
            raise ASN1DecodeError('BOOLEAN content must be 0x00 or 0xff')

        return bool(content[0])


@DERTag(INTEGER, (int,))
class _Integer(DERType):
    ''

    @staticmethod
    def encode(value: object) -> bytes:
        ''

        i = cast(int, value)
        l = i.bit_length()
        l = l // 8 + 1 if l % 8 == 0 else (l + 7) // 8
        result = i.to_bytes(l, 'big', signed=True)
        return result[1:] if result.startswith(b'\xff\x80') else result

    @classmethod
    def decode(cls, constructed: bool, content: bytes) -> int:
        ''

        if constructed:
            raise ASN1DecodeError('INTEGER should not be constructed')

        return int.from_bytes(content, 'big', signed=True)


@DERTag(OCTET_STRING, (bytes, bytearray))
class _OctetString(DERType):
    ''

    @staticmethod
    def encode(value: object) -> bytes:
        ''

        return cast(bytes, value)

    @classmethod
    def decode(cls, constructed: bool, content: bytes) -> bytes:
        ''

        if constructed:
            raise ASN1DecodeError('OCTET STRING should not be constructed')

        return content


@DERTag(UTF8_STRING, (str,))
class _UTF8String(DERType):
    ''

    @staticmethod
    def encode(value: object) -> bytes:
        ''

        return cast(str, value).encode('utf-8')

    @classmethod
    def decode(cls, constructed: bool, content: bytes) -> str:
        ''

        if constructed:
            raise ASN1DecodeError('UTF8 STRING should not be constructed')

        return content.decode('utf-8')


@DERTag(SEQUENCE, (list, tuple), constructed=True)
class _Sequence(DERType):
    ''

    @staticmethod
    def encode(value: object) -> bytes:
        ''

        seq_value = cast(Sequence[object], value)
        return b''.join(der_encode(item) for item in seq_value)

    @classmethod
    def decode(cls, constructed: bool, content: bytes) -> Sequence[object]:
        ''

        if not constructed:
            raise ASN1DecodeError('SEQUENCE should always be constructed')

        offset = 0
        length = len(content)

        value = []
        while offset < length:
            item, consumed = der_decode_partial(content[offset:])
            value.append(item)
            offset += consumed

        return tuple(value)


@DERTag(SET, (set, frozenset), constructed=True)
class _Set(DERType):
    ''

    @staticmethod
    def encode(value: object) -> bytes:
        ''

        set_value = cast(Union[FrozenSet[object], Set[object]], value)
        return b''.join(sorted(der_encode(item) for item in set_value))

    @classmethod
    def decode(cls, constructed: bool, content: bytes) -> FrozenSet[object]:
        ''

        if not constructed:
            raise ASN1DecodeError('SET should always be constructed')

        offset = 0
        length = len(content)

        value = set()
        while offset < length:
            item, consumed = der_decode_partial(content[offset:])
            value.add(item)
            offset += consumed

        return frozenset(value)


@DERTag(BIT_STRING)
class BitString(DERType):
    ''












    def __init__(self, value: object, unused: int = 0, named: bool = False):
        if unused < 0 or unused > 7:
            raise ASN1EncodeError('Unused bit count must be between 0 and 7')

        if isinstance(value, bytes):
            if unused:
                if not value:
                    raise ASN1EncodeError('Can\'t have unused bits with empty '
                                          'value')
                elif value[-1] & ((1 << unused) - 1):
                    raise ASN1EncodeError('Unused bits in value should be '
                                          'zero')
        elif isinstance(value, str):
            if unused:
                raise ASN1EncodeError('Unused bit count should not be set '
                                      'when providing a string')

            used = len(value) % 8
            unused = 8 - used if used else 0
            value += unused * '0'
            value = bytes(int(value[i:i+8], 2)
                          for i in range(0, len(value), 8))
        else:
            raise ASN1EncodeError('Unexpected type of bit string value')

        if named:
            while value and not value[-1] & (1 << unused):
                unused += 1
                if unused == 8:
                    value = value[:-1]
                    unused = 0

        self.value = value
        self.unused = unused

    def __str__(self) -> str:
        result = ''.join(bin(b)[2:].zfill(8) for b in self.value)
        if self.unused:
            result = result[:-self.unused]
        return result

    def __repr__(self) -> str:
        return f"BitString('{self}')"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, BitString): # pragma: no cover
            return NotImplemented

        return self.value == other.value and self.unused == other.unused

    def __hash__(self) -> int:
        return hash((self.value, self.unused))

    @staticmethod
    def encode(value: object) -> bytes:
        ''

        bitstr_value = cast('BitString', value)
        return bytes((bitstr_value.unused,)) + bitstr_value.value

    @classmethod
    def decode(cls, constructed: bool, content: bytes) -> 'BitString':
        ''

        if constructed:
            raise ASN1DecodeError('BIT STRING should not be constructed')

        if not content or content[0] > 7:
            raise ASN1DecodeError('Invalid unused bit count')

        return cls(content[1:], unused=content[0])


@DERTag(IA5_STRING)
class IA5String(DERType):
    ''

    def __init__(self, value: Union[bytes, bytearray]):
        self.value = value

    def __str__(self) -> str:
        return self.value.decode('ascii')

    def __repr__(self) -> str:
        return f'IA5String({self.value!r})'

    def __eq__(self, other: object) -> bool: # pragma: no cover
        if not isinstance(other, IA5String):
            return NotImplemented

        return self.value == other.value

    def __hash__(self) -> int:
        return hash(self.value)

    @staticmethod
    def encode(value: object) -> bytes:
        ''







        return cast('IA5String', value).value

    @classmethod
    def decode(cls, constructed: bool, content: bytes) -> 'IA5String':
        ''

        if constructed:
            raise ASN1DecodeError('IA5 STRING should not be constructed')





        return cls(content)


@DERTag(OBJECT_IDENTIFIER)
class ObjectIdentifier(DERType):
    ''











    def __init__(self, value: str):
        self.value = value

    def __str__(self) -> str:
        return self.value

    def __repr__(self) -> str:
        return f"ObjectIdentifier('{self.value}')"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ObjectIdentifier): # pragma: no cover
            return NotImplemented

        return self.value == other.value

    def __hash__(self) -> int:
        return hash(self.value)

    @staticmethod
    def encode(value: object) -> bytes:
        ''

        def _bytes(component: int) -> bytes:
            ''

            if component < 0:
                raise ASN1EncodeError('Components of object identifier must '
                                      'be greater than or equal to 0')

            result = [component & 0x7f]
            while component >= 0x80:
                component >>= 7
                result.append(0x80 | (component & 0x7f))

            return bytes(result[::-1])

        oid_value = cast('ObjectIdentifier', value)

        try:
            components = [int(c) for c in oid_value.value.split('.')]
        except ValueError:
            raise ASN1EncodeError('Component values must be '
                                  'integers') from None

        if len(components) < 2:
            raise ASN1EncodeError('Object identifiers must have at least two '
                                  'components')
        elif components[0] < 0 or components[0] > 2:
            raise ASN1EncodeError('First component of object identifier must '
                                  'be between 0 and 2')
        elif components[0] < 2 and (components[1] < 0 or components[1] > 39):
            raise ASN1EncodeError('Second component of object identifier must '
                                  'be between 0 and 39')

        components[0:2] = [components[0]*40 + components[1]]
        return b''.join(_bytes(c) for c in components)

    @classmethod
    def decode(cls, constructed: bool, content: bytes) -> 'ObjectIdentifier':
        ''

        if constructed:
            raise ASN1DecodeError('OBJECT IDENTIFIER should not be '
                                  'constructed')

        if not content:
            raise ASN1DecodeError('Empty object identifier')

        b = content[0]
        components = list(divmod(b, 40)) if b < 80 else [2, b-80]

        component = 0
        for b in content[1:]:
            if b == 0x80 and component == 0:
                raise ASN1DecodeError('Invalid component')
            elif b < 0x80:
                components.append(component | b)
                component = 0
            else:
                component |= b & 0x7f
                component <<= 7

        if component:
            raise ASN1DecodeError('Incomplete component')

        return cls('.'.join(str(c) for c in components))


def der_encode(value: object) -> bytes:
    ''























    t = type(value)
    if t in (RawDERObject, TaggedDERObject):
        value = cast(Union[RawDERObject, TaggedDERObject], value)
        identifier = value.encode_identifier()
        content = value.encode(value)
    elif t in _der_class_by_type:
        cls = _der_class_by_type[t]
        identifier = cls.identifier
        content = cls.encode(value)
    else:
        raise ASN1EncodeError(f'Cannot DER encode type {t.__name__}')

    length = len(content)
    if length < 0x80:
        len_bytes = bytes((length,))
    else:
        len_bytes = length.to_bytes((length.bit_length() + 7) // 8, 'big')
        len_bytes = bytes((0x80 | len(len_bytes),)) + len_bytes

    return identifier + len_bytes + content


def der_decode_partial(data: bytes) -> Tuple[object, int]:
    ''

    if len(data) < 2:
        raise ASN1DecodeError('Incomplete data')

    tag = data[0]
    asn1_class, constructed, tag = tag >> 6, bool(tag & 0x20), tag & 0x1f
    offset = 1
    if tag == 0x1f:
        tag = 0
        for b in data[offset:]:
            offset += 1

            if b < 0x80:
                tag |= b
                break
            else:
                tag |= b & 0x7f
                tag <<= 7
        else:
            raise ASN1DecodeError('Incomplete tag')

    if offset >= len(data):
        raise ASN1DecodeError('Incomplete data')

    length = data[offset]
    offset += 1
    if length > 0x80:
        len_size = length & 0x7f
        length = int.from_bytes(data[offset:offset+len_size], 'big')
        offset += len_size
    elif length == 0x80:
        raise ASN1DecodeError('Indefinite length not allowed')

    end = offset + length
    content = data[offset:end]

    if end > len(data):
        raise ASN1DecodeError('Incomplete data')

    if asn1_class == UNIVERSAL and tag in _der_class_by_tag:
        cls = _der_class_by_tag[tag]
        value = cls.decode(constructed, content)
    elif constructed:
        value = TaggedDERObject(tag, der_decode(content), asn1_class)
    else:
        value = RawDERObject(tag, content, asn1_class)

    return value, end


def der_decode(data: bytes) -> object:
    ''



























    value, end = der_decode_partial(data)

    if end < len(data):
        raise ASN1DecodeError('Data contains unexpected bytes at end')

    return value
