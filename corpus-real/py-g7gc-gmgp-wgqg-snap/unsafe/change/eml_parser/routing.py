''

import re
import typing

import eml_parser.decode
import eml_parser.regexes


def noparenthesis(line: str) -> str:
    ''










    if not line:
        return line

    line_ = line

    while True:
        lline = line_
        line_ = eml_parser.regexes.noparenthesis_regex.sub('', line_)
        if lline == line_:
            break

    return line_


def cleanline(line: str) -> str:
    ''







    if line == '':
        return line

    return eml_parser.regexes.cleanline_regex.sub('', line)


def get_domain_ip(line: str) -> list[str]:
    ''







    m = eml_parser.regexes.dom_regex.findall(' ' + line) + eml_parser.regexes.ipv4_regex.findall(line) + eml_parser.regexes.ipv6_regex.findall(line)

    return list(set(m))


def parserouting(line: str) -> dict[str, typing.Any]:
    ''














    out = {}  # type: typing.Dict[str, typing.Any]  # Result
    out['src'] = line
    line = line.lower()
    npline = line.replace(')', ' ) ')
    npline = npline.replace('(', ' ( ')
    npline = npline.replace(';', ' ; ')
    npline = noparenthesis(npline)
    npline = ' '.join(npline.split())
    npline = npline.strip('\n')
    raw_find_data = eml_parser.regexes.date_regex.findall(npline)


    if ' received: ' in npline:
        out['warning'] = ['Merged Received headers']
        return out

    if raw_find_data:
        npdate = raw_find_data[0]
        npdate = npdate.lstrip(';')
        npdate = npdate.strip()
    else:
        npdate = ''

    npline = npline.replace(npdate, '')
    npline = npline.strip(' ')

    borders = ['from ', 'by ', 'with ', 'for ']
    result: list[dict[str, typing.Any]] = []


    for word in borders:
        candidate = list(borders)
        candidate.remove(word)
        for endword in candidate:
            if word in npline:
                loc = npline.find(word)
                end = npline.find(endword)
                if end < loc or end == -1:
                    end = 0xFFFFFFF
                result.append({'name_in': word, 'pos': loc, 'name_out': endword, 'weight': end + loc})



    if not result:
        out['warning'] = ['Nothing Parsable']
        return out

    tout = []
    for word in borders:
        result_max = 0xFFFFFFFF
        line_max: dict[str, typing.Any] = {}
        for eline in result:
            if eline['name_in'] == word and eline['weight'] <= result_max:
                result_max = eline['weight']
                line_max = eline

        if line_max:
            tout.append([line_max.get('pos'), line_max.get('name_in')])



    tout = sorted(tout, key=lambda x: typing.cast('int', x[0]))


    reg = ''
    for item in tout:
        reg += item[1] + '(?P<' + item[1].strip() + '>.*)'  # type: ignore
    if npdate:

        reg += eml_parser.regexes.escape_special_regex_chars.sub(r"""\\\1""", npdate)

    reparse = re.compile(reg)
    reparseg = reparse.search(line)


    if reparseg is not None:
        for item in borders:  # type: ignore
            try:
                out[item.strip()] = cleanline(reparseg.group(item.strip()))  # type: ignore
            except (LookupError, ValueError, AttributeError):
                pass

    if npdate:
        out['date'] = eml_parser.decode.robust_string2date(npdate)



    if out.get('for'):

        if ' from ' in out.get('for', ''):
            temp = re.split(' from ', out['for'])
            out['for'] = temp[0]
            out['from'] = f"""{out['from']} {' '.join(temp[1:])}"""

        m = eml_parser.regexes.email_regex.findall(out['for'])
        if m:
            out['for'] = list(set(m))
        else:
            del out['for']


    if out.get('from'):
        out['from'] = get_domain_ip(out['from'])
        if not out.get('from', []):
            del out['from']


    if out.get('by'):
        out['by'] = get_domain_ip(out['by'])
        if not out.get('by', []):
            del out['by']

    return out
