''

import datetime
import email
import email.errors
import email.header
import email.policy
import email.utils
import json
import logging
import typing

import charset_normalizer
import dateutil.parser

import eml_parser.regexes































logger = logging.getLogger(__name__)

default_date = '1970-01-01T00:00:00+00:00'


def decode_field(field: str) -> str:
    ''










    try:
        _decoded = email.header.decode_header(field)
    except email.errors.HeaderParseError:
        return field

    string = ''

    for _text, charset in _decoded:
        if charset:
            string += decode_string(_text, charset)
        elif isinstance(_text, bytes):

            string += _text.decode('utf-8', 'ignore')
        else:
            string += _text

    return string


def decode_string(string: bytes, encoding: str | None = None) -> str:
    ''













    if string == b'':
        return ''

    if encoding is not None:
        try:
            return string.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            pass

    value = str(charset_normalizer.from_bytes(string).best())

    if value is None:
        text = ''

        for e in ('latin1', 'utf-8'):
            try:
                text = string.decode(e)
            except UnicodeDecodeError:
                pass
            else:
                break

        if text == '':
            value = string.decode('ascii', 'ignore')
        else:
            value = text

    return value


def workaround_bug_27257(msg: email.message.Message, header: str) -> list[str]:
    ''








    return_value: list[str] = []

    for value in workaround_field_value_parsing_errors(msg, header):
        if value != '':
            m = eml_parser.regexes.email_regex.findall(value)
            if m:
                return_value += list(set(m))

    return return_value


def workaround_field_value_parsing_errors(msg: email.message.Message, header: str) -> list[str]:
    ''








    if msg.policy == email.policy.compat32:
        new_policy = None
    else:
        new_policy = msg.policy

    msg.policy = email.policy.compat32
    return_value = []

    for value in msg.get_all(header, []):
        if value != '':
            return_value.append(value)

    if new_policy is not None:
        msg.policy = new_policy

    return return_value


def robust_string2date(line: str) -> datetime.datetime:
    ''

















    if line == '':
        return datetime.datetime.fromisoformat(default_date)

    try:
        date_ = email.utils.parsedate_to_datetime(line)
    except (TypeError, ValueError, LookupError):
        logger.debug('Exception parsing date "%s"', line, exc_info=True)

        try:
            date_ = dateutil.parser.parse(line)
        except (AttributeError, ValueError, OverflowError):

            return datetime.datetime.fromisoformat(default_date)

    if date_.tzname() is None:
        return date_.replace(tzinfo=datetime.timezone.utc)

    return date_


def json_serial(obj: typing.Any) -> str | None:
    ''
    if isinstance(obj, datetime.datetime):
        if obj.tzinfo is not None:
            serial = obj.astimezone(datetime.timezone.utc).isoformat()
        else:
            serial = obj.isoformat()

        return serial

    raise TypeError(f'Type not serializable - {str(type(obj))}')


def export_to_json(parsed_msg: dict, sort_keys: bool = False) -> str:
    ''










    return json.dumps(parsed_msg, default=json_serial, sort_keys=sort_keys, indent=2)


def rfc2047_decode(value: str) -> str:
    ''







    if not value:
        return value

    parsed = ''

    for k, v in email.header.decode_header(value):
        if v is None:
            parsed += k.decode('ascii', errors='ignore')

        else:
            parsed += k.decode(v, errors='replace')

    return parsed
