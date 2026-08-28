''



import json
import logging
import traceback
from functools import partial
from http.cookies import SimpleCookie
from urllib.parse import urlparse, urlunparse

from tornado.log import LogFormatter, access_log
from tornado.web import HTTPError, StaticFileHandler

from .handlers.pages import HealthCheckHandler
from .metrics import prometheus_log_method


def coroutine_frames(all_frames):
    ''



    useful_frames = []
    for frame in all_frames:
        if frame[0] == '<string>' and frame[2] == 'raise_exc_info':
            continue


        elif frame[0].endswith('tornado/gen.py') and frame[2] in {
            'run',
            'wrapper',
            '__init__',
        }:
            continue
        elif frame[0].endswith('tornado/concurrent.py') and frame[2] == 'result':
            continue
        useful_frames.append(frame)
    return useful_frames


def coroutine_traceback(typ, value, tb):
    ''







    all_frames = traceback.extract_tb(tb)
    useful_frames = coroutine_frames(all_frames)

    tb_list = ['Traceback (most recent call last):\n']
    tb_list.extend(traceback.format_list(useful_frames))
    tb_list.extend(traceback.format_exception_only(typ, value))
    return tb_list


class CoroutineLogFormatter(LogFormatter):
    ''

    def formatException(self, exc_info):
        return ''.join(coroutine_traceback(*exc_info))





SCRUB_PARAM_KEYS = ('token', 'auth', 'key', 'code', 'state', '_xsrf')


def _scrub_uri(uri):
    ''
    if '/api/authorizations/cookie/' in uri or '/api/authorizations/token/' in uri:
        uri = uri.rsplit('/', 1)[0] + '/[secret]'
    parsed = urlparse(uri)
    if parsed.query:



        parts = parsed.query.split('&')
        changed = False
        for i, s in enumerate(parts):
            if '=' in s:
                key, value = s.split('=', 1)
                for substring in SCRUB_PARAM_KEYS:
                    if substring in key:
                        parts[i] = key + '=[secret]'
                        changed = True
        if changed:
            parsed = parsed._replace(query='&'.join(parts))
            return urlunparse(parsed)
    return uri


def _scrub_headers(headers):
    ''
    headers = dict(headers)
    if 'Authorization' in headers:
        auth = headers['Authorization']
        if ' ' in auth:
            auth_type = auth.split(' ', 1)[0]
        else:

            auth_type = ''
        headers['Authorization'] = f'{auth_type} [secret]'
    if 'Cookie' in headers:
        try:
            c = SimpleCookie(headers['Cookie'])
        except Exception as e:

            headers['Cookie'] = f"Invalid Cookie: {e}"
        else:
            redacted = []
            for name in c.keys():
                redacted.append(f"{name}=[secret]")
            headers['Cookie'] = '; '.join(redacted)
    return headers





def log_request(handler):
    ''







    status = handler.get_status()
    request = handler.request
    if status == 304 or (
        status < 300 and isinstance(handler, (StaticFileHandler, HealthCheckHandler))
    ):

        log_level = logging.DEBUG
    elif status < 400:
        log_level = logging.INFO
    elif status < 500:
        log_level = logging.WARNING
    else:
        log_level = logging.ERROR

    uri = _scrub_uri(request.uri)
    headers = _scrub_headers(request.headers)

    request_time = 1000.0 * handler.request.request_time()


    if request_time >= 1000 and log_level < logging.INFO:
        log_level = logging.INFO

    log_method = partial(access_log.log, log_level)

    try:
        user = handler.current_user
    except (HTTPError, RuntimeError):
        username = ''
    else:
        if user is None:
            username = ''
        elif isinstance(user, str):
            username = user
        elif isinstance(user, dict):
            username = user['name']
        else:
            username = user.name

    ns = dict(
        status=status,
        method=request.method,
        ip=request.remote_ip,
        uri=uri,
        request_time=request_time,
        user=username,
        location='',
    )
    msg = "{status} {method} {uri}{location} ({user}@{ip}) {request_time:.2f}ms"
    if status >= 500 and status not in {502, 503}:
        log_method(json.dumps(headers, indent=2))
    elif status in {301, 302}:



        location = handler._headers.get('Location')
        if location:
            ns['location'] = f' -> {_scrub_uri(location)}'
    log_method(msg.format(**ns))
    prometheus_log_method(handler)
