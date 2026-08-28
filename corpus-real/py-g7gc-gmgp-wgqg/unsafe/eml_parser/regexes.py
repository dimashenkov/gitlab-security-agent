# pylint: disable=line-too-long

''

try:
    import regex as re
except ImportError:
    import re

__author__ = 'Toth Georges, Jung Paul'
__email__ = 'georges@trypill.org, georges.toth@govcert.etat.lu'
__copyright__ = 'Copyright 2013-2014 Georges Toth, Copyright 2013-present GOVCERT Luxembourg'
__license__ = 'AGPL v3+'



email_no_force_tld_regex = re.compile(r"""([a-zA-Z0-9.!#$%&'*+-/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*)""", re.MULTILINE)
email_force_tld_regex = re.compile(r"""([a-zA-Z0-9.!#$%&'*+-/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)""", re.MULTILINE)
email_regex = email_no_force_tld_regex


email_regex_rfc2047 = re.compile(r"""=\?{1}([\w\S]+)\?{1}([B|Q|b|q])\?{1}([\w\S]+)\?{1}=""")

recv_dom_regex = re.compile(r"""(?:(?:from|by)\s+)([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]{2,})+)""", re.MULTILINE)

dom_regex = re.compile(r"""(?:^|[\s(/<>|@'=])([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]{2,})+)(?=$|[\?\s#&/<>')])""", re.MULTILINE)

ipv4_regex = re.compile(r"""(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""")


ipv6_regex = re.compile(
    r"""((?:[0-9a-f]{1,4}:){6}(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|::(?:[0-9a-f]{1,4}:){5}(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9a-f]{1,4})?::(?:[0-9a-f]{1,4}:){4}(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9a-f]{1,4}:[0-9a-f]{1,4})?::(?:[0-9a-f]{1,4}:){3}(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9a-f]{1,4}:){,2}[0-9a-f]{1,4})?::(?:[0-9a-f]{1,4}:){2}(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9a-f]{1,4}:){,3}[0-9a-f]{1,4})?::[0-9a-f]{1,4}:(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9a-f]{1,4}:){,4}[0-9a-f]{1,4})?::(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9a-f]{1,4}:){,5}[0-9a-f]{1,4})?::[0-9a-f]{1,4}|(?:(?:[0-9a-f]{1,4}:){,6}[0-9a-f]{1,4})?::)""",
    flags=re.IGNORECASE,
)









url_regex_comma = re.compile(r',(?=https?|ftps?)', flags=re.IGNORECASE)
url_regex_www_comma = re.compile(r',(?=https?|ftps?|www\d{0,3})', flags=re.IGNORECASE)

url_regex_simple = re.compile(
    r"""
\b
(?:https?|ftps?):
(?:/{1,3}|[a-z0-9%])
(?:
  \[[0-9a-f:.]{2,40}(?:%[^\x00-\x20\s\]]{1,100})?\]
|
  [^\x00-\x20\s`()<>{}\[\]\/'"«»“”‘’]+
)
(?:[\w\-._~%!$&'()*+,;=:/?#\[\]@\U00001000-\U0010FFFF]*[^\x00-\x20\s`!\[\]{};:'".,<>«»“”‘’])?
""",
    flags=re.IGNORECASE | re.VERBOSE,
)
url_regex_www = re.compile(
    r"""
(?:
# http/ftp schemes
    \b
    (?:https?|ftps?):
    (?:/{1,3}|[a-z0-9%])
    (?:
      \[[0-9a-f:.]{2,40}(?:%[^\x00-\x20\s\]]{1,100})?\]
    |
      [^\x00-\x20\s`()<>{}\[\]\/'"«»“”‘’]+
    )
    (?:[\w\-._~%!$&'()*+,;=:/?#\[\]@\U00001000-\U0010FFFF]*[^\x00-\x20\s`!\[\]{};:'".,<>«»“”‘’])?
|
# www address  (any preceding matched character needs to be removed afterward)
    (?:
    ^|[ \t\n\r\f\v\'\"«»“”‘’])
    www\d{0,3}[.](?:[-\w\u0900-\u2017\u2020-\U0010FFFF]{1,250}[.]){1,250}[-0-9a-z\w\u0900-\u0DFF]{2,30}[.]*  # Host Simple TLD regex
    (?::[0]*[1-9][0-9]{0,4})?  # Port
    (?:[\/#?](?:[\w\-._~%!$&'()*+,;=:/?#\[\]@\U00001000-\U0010FFFF]*[^\x00-\x20\s`!\[\]{};:'\".,<>«»“”‘’])) # Path, etc.
)
""",
    flags=re.IGNORECASE | re.VERBOSE,
)




url_regex_href = re.compile(
    r"""
<(?:a[\s\/]+[^>]*?href
 |img[\s\/]+[^>]*?src)
[\s\/]*=[\s\/]*
((?:[\"][^\"]+)|[\'][^\']+|[^\s>]+)
""",
    flags=re.IGNORECASE | re.VERBOSE,
)

date_regex = re.compile(r""";[ \w\s:,+\-()]+$""")
cleanline_regex = re.compile(r"""(^[;\s]{0,}|[;\s]{0,}$)""")

escape_special_regex_chars = re.compile(r"""([\^$\[\]()+?.])""")

window_slice_regex = re.compile(r"""\s""")
