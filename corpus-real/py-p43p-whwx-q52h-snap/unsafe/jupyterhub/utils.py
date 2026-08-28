''



import asyncio
import concurrent.futures
import errno
import functools
import hashlib
import inspect
import os
import random
import re
import secrets
import socket
import ssl
import string
import sys
import threading
import time
import uuid
import warnings
from binascii import b2a_hex
from datetime import datetime, timezone
from functools import lru_cache
from hmac import compare_digest
from operator import itemgetter
from urllib.parse import quote

if sys.version_info >= (3, 10):
    from contextlib import aclosing
else:
    from async_generator import aclosing

import idna
from sqlalchemy.exc import SQLAlchemyError
from tornado import gen, ioloop, web
from tornado.httpclient import AsyncHTTPClient, HTTPError
from tornado.log import app_log


def _bool_env(key, default=False):
    ''




    value = os.environ.get(key, "")
    if value == "":
        return default
    if value.lower() in {"0", "false"}:
        return False
    else:
        return True



def asyncio_all_tasks(loop=None):
    warnings.warn(
        "jupyterhub.utils.asyncio_all_tasks is deprecated in JupyterHub 2.4."
        " Use asyncio.all_tasks().",
        DeprecationWarning,
        stacklevel=2,
    )
    return asyncio.all_tasks(loop=loop)


def asyncio_current_task(loop=None):
    warnings.warn(
        "jupyterhub.utils.asyncio_current_task is deprecated in JupyterHub 2.4."
        " Use asyncio.current_task().",
        DeprecationWarning,
        stacklevel=2,
    )
    return asyncio.current_task(loop=loop)


def random_port():
    ''
    sock = socket.socket()
    sock.bind(('', 0))
    port = sock.getsockname()[1]
    sock.close()
    return port



ISO8601_ms = '%Y-%m-%dT%H:%M:%S.%fZ'
ISO8601_s = '%Y-%m-%dT%H:%M:%SZ'


def isoformat(dt):
    ''





    if dt is None:
        return None
    if dt.tzinfo:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt.isoformat() + 'Z'


def can_connect(ip, port):
    ''



    if ip in {'', '0.0.0.0'}:
        ip = '127.0.0.1'
    elif ip == "::":
        ip = "::1"
    try:
        socket.create_connection((ip, port)).close()
    except OSError as e:
        if e.errno not in {errno.ECONNREFUSED, errno.ETIMEDOUT}:
            app_log.error("Unexpected error connecting to %s:%i %s", ip, port, e)
        else:
            app_log.debug("Server at %s:%i not ready: %s", ip, port, e)
        return False
    else:
        return True


def make_ssl_context(
    keyfile,
    certfile,
    cafile=None,
    verify=None,
    check_hostname=None,
    purpose=ssl.Purpose.SERVER_AUTH,
):
    ''








    if not keyfile or not certfile:
        return None
    if verify is not None:
        purpose = ssl.Purpose.SERVER_AUTH if verify else ssl.Purpose.CLIENT_AUTH
        warnings.warn(
            f"make_ssl_context(verify={verify}) is deprecated in jupyterhub 2.4."
            f" Use make_ssl_context(purpose={purpose!s}).",
            DeprecationWarning,
            stacklevel=2,
        )
    if check_hostname is not None:
        purpose = ssl.Purpose.SERVER_AUTH if check_hostname else ssl.Purpose.CLIENT_AUTH
        warnings.warn(
            f"make_ssl_context(check_hostname={check_hostname}) is deprecated in jupyterhub 2.4."
            f" Use make_ssl_context(purpose={purpose!s}).",
            DeprecationWarning,
            stacklevel=2,
        )

    ssl_context = ssl.create_default_context(purpose, cafile=cafile)

    ssl_context.verify_mode = ssl.CERT_REQUIRED

    if purpose == ssl.Purpose.SERVER_AUTH:

        ssl_context.check_hostname = True
    ssl_context.load_default_certs()

    ssl_context.load_cert_chain(certfile, keyfile)
    if check_hostname is not None:
        ssl_context.check_hostname = check_hostname
    return ssl_context



AnyTimeoutError = (gen.TimeoutError, asyncio.TimeoutError, TimeoutError)


async def exponential_backoff(
    pass_func,
    fail_message,
    start_wait=0.2,
    scale_factor=2,
    max_wait=5,
    timeout=10,
    timeout_tolerance=0.1,
    *args,
    **kwargs,
):
    ''

















































    loop = ioloop.IOLoop.current()
    deadline = loop.time() + timeout


    if timeout_tolerance:
        tol = timeout_tolerance * timeout
        deadline = random.uniform(deadline - tol, deadline + tol)
    scale = 1
    while True:
        ret = await maybe_future(pass_func(*args, **kwargs))

        if ret:
            return ret
        remaining = deadline - loop.time()
        if remaining < 0:

            break



        limit = min(max_wait, start_wait * scale)
        if limit < max_wait:
            scale *= scale_factor
        dt = min(remaining, random.uniform(0, limit))
        await asyncio.sleep(dt)
    raise asyncio.TimeoutError(fail_message)


async def wait_for_server(ip, port, timeout=10):
    ''
    if ip in {'', '0.0.0.0'}:
        ip = '127.0.0.1'
    elif ip == "::":
        ip = "::1"
    display_ip = fmt_ip_url(ip)
    app_log.debug("Waiting %ss for server at %s:%s", timeout, display_ip, port)
    tic = time.perf_counter()
    await exponential_backoff(
        lambda: can_connect(ip, port),
        f"Server at {display_ip}:{port} didn't respond in {timeout} seconds",
        timeout=timeout,
    )
    toc = time.perf_counter()
    app_log.debug("Server at %s:%s responded in %.2fs", display_ip, port, toc - tic)


async def wait_for_http_server(url, timeout=10, ssl_context=None):
    ''



    client = AsyncHTTPClient()
    if ssl_context:
        client.ssl_options = ssl_context

    app_log.debug("Waiting %ss for server at %s", timeout, url)
    tic = time.perf_counter()

    async def is_reachable():
        try:
            r = await client.fetch(url, follow_redirects=False)
            return r
        except HTTPError as e:
            if e.code >= 500:

                if e.code != 599:


                    app_log.warning(
                        "Server at %s responded with error: %s", url, e.code
                    )
            else:
                app_log.debug("Server at %s responded with %s", url, e.code)
                return e.response
        except OSError as e:
            if e.errno not in {
                errno.ECONNABORTED,
                errno.ECONNREFUSED,
                errno.ECONNRESET,
            }:
                app_log.warning("Failed to connect to %s (%s)", url, e)
        except Exception as e:
            app_log.warning("Error while waiting for server %s (%s)", url, e)
        return False

    re = await exponential_backoff(
        is_reachable,
        f"Server at {url} didn't respond in {timeout} seconds",
        timeout=timeout,
    )
    toc = time.perf_counter()
    app_log.debug("Server at %s responded in %.2fs", url, toc - tic)
    return re



def auth_decorator(check_auth):
    ''





    def decorator(method):
        def decorated(self, *args, **kwargs):
            check_auth(self, **kwargs)
            return method(self, *args, **kwargs)


        decorated.__name__ = method.__name__
        decorated.__doc__ = method.__doc__
        return decorated

    decorator.__name__ = check_auth.__name__
    decorator.__doc__ = check_auth.__doc__
    return decorator


@auth_decorator
def token_authenticated(self):
    ''



    if self.get_current_user_token() is None:
        raise web.HTTPError(403)


@auth_decorator
def authenticated_403(self):
    ''




    if self.current_user is None:
        raise web.HTTPError(403)


def admin_only(f):
    ''


    warnings.warn(
        """@jupyterhub.utils.admin_only is deprecated in JupyterHub 2.0.

        Use the new `@jupyterhub.scopes.needs_scope` decorator to resolve permissions,
        or check against `self.current_user.parsed_scopes`.
        """,
        DeprecationWarning,
        stacklevel=2,
    )


    @auth_decorator
    def admin_only(self):
        ''
        user = self.current_user
        if user is None or not user.admin:
            raise web.HTTPError(403)

    return admin_only(f)


@auth_decorator
def metrics_authentication(self):
    ''
    if not self.authenticate_prometheus:
        return
    scope = 'read:metrics'
    if scope not in self.parsed_scopes:
        raise web.HTTPError(403, f"Access to metrics requires scope '{scope}'")





def new_token(*args, **kwargs):
    ''



    return uuid.uuid4().hex


def hash_token(token, salt=8, rounds=16384, algorithm='sha512'):
    ''



    h = hashlib.new(algorithm)
    if isinstance(salt, int):
        salt = b2a_hex(secrets.token_bytes(salt))
    if isinstance(salt, bytes):
        bsalt = salt
        salt = salt.decode('utf8')
    else:
        bsalt = salt.encode('utf8')
    btoken = token.encode('utf8', 'replace')
    h.update(bsalt)
    for i in range(rounds):
        h.update(btoken)
    digest = h.hexdigest()

    return f"{algorithm}:{rounds}:{salt}:{digest}"


def compare_token(compare, token):
    ''



    algorithm, srounds, salt, _ = compare.split(':')
    hashed = hash_token(
        token, salt=salt, rounds=int(srounds), algorithm=algorithm
    ).encode('utf8')
    compare = compare.encode('utf8')
    if compare_digest(compare, hashed):
        return True
    return False


def url_escape_path(value):
    ''
    return quote(value, safe='@~')


def url_path_join(*pieces):
    ''







    pieces = list(pieces)
    while pieces and not pieces[-1]:
        del pieces[-1]
    if not pieces:
        return ""
    initial = pieces[0].startswith('/')
    final = pieces[-1].endswith('/')
    stripped = [s.strip('/') for s in pieces]
    result = '/'.join(s for s in stripped if s)

    if initial:
        result = '/' + result
    if final:
        result = result + '/'
    if result == '//':
        result = '/'

    return result


def print_ps_info(file=sys.stderr):
    ''



    try:
        import psutil
    except ImportError:

        warnings.warn(
            "psutil unavailable. Install psutil to get CPU and memory stats",
            stacklevel=2,
        )
        return
    p = psutil.Process()

    cpu = p.cpu_percent(0.1)
    if cpu >= 10:
        cpu_s = str(int(cpu))
    else:
        cpu_s = f"{cpu:.1f}"


    rss = p.memory_info().rss
    if rss >= 1e9:
        mem_s = f'{rss / 1e9:.1f}G'
    elif rss >= 1e7:
        mem_s = f'{rss / 1e6:.0f}M'
    elif rss >= 1e6:
        mem_s = f'{rss / 1e6:.1f}M'
    else:
        mem_s = f'{rss / 1e3:.0f}k'


    cpulen = max(len(cpu_s), 4)
    memlen = max(len(mem_s), 3)
    fd_s = str(p.num_fds())
    fdlen = max(len(fd_s), 3)
    threadlen = len('threads')

    print(
        "{} {} {} {}".format(
            '%CPU'.ljust(cpulen), 'MEM'.ljust(memlen), 'FDs'.ljust(fdlen), 'threads'
        ),
        file=file,
    )

    print(
        f"{cpu_s.ljust(cpulen)} {mem_s.ljust(memlen)} {fd_s.ljust(fdlen)} {str(p.num_threads()).ljust(7)}",
        file=file,
    )


    print('', file=file)


def print_stacks(file=sys.stderr):
    ''














    import traceback

    from .log import coroutine_frames

    print(f"Active threads: {threading.active_count()}", file=file)
    for thread in threading.enumerate():
        print(f"Thread {thread.name}:", end='', file=file)
        frame = sys._current_frames()[thread.ident]
        stack = traceback.extract_stack(frame)
        if thread is threading.current_thread():


            stack = stack[:-2]
        stack = coroutine_frames(stack)
        if stack:
            last_frame = stack[-1]
            if (
                last_frame[0].endswith('threading.py')
                and last_frame[-1] == 'waiter.acquire()'
            ) or (
                last_frame[0].endswith('thread.py')
                and last_frame[-1].endswith('work_queue.get(block=True)')
            ):



                print(' idle', file=file)
                continue

        print(''.join(['\n'] + traceback.format_list(stack)), file=file)




    tasks = asyncio_all_tasks()
    if tasks:
        print(f"AsyncIO tasks: {len(tasks)}")
        for task in tasks:
            task.print_stack(file=file)


def maybe_future(obj):
    ''












    if inspect.isawaitable(obj):

        return asyncio.ensure_future(obj)
    elif isinstance(obj, concurrent.futures.Future):
        return asyncio.wrap_future(obj)
    else:


        f = asyncio.Future()
        f.set_result(obj)
        return f


async def iterate_until(deadline_future, generator):
    ''














    async with aclosing(generator.__aiter__()) as aiter:
        while True:
            item_future = asyncio.ensure_future(aiter.__anext__())
            await asyncio.wait(
                [item_future, deadline_future], return_when=asyncio.FIRST_COMPLETED
            )
            if item_future.done():
                try:
                    yield item_future.result()
                except (StopAsyncIteration, asyncio.CancelledError):
                    break
            elif deadline_future.done():



                if not item_future.cancelled():
                    item_future.cancel()

                try:
                    await item_future
                except asyncio.CancelledError:
                    pass
                break
            else:

                continue


def utcnow(*, with_tz=True):
    ''






    now = datetime.now(timezone.utc)
    if not with_tz:
        now = now.replace(tzinfo=None)
    return now


def _parse_accept_header(accept):
    ''







    result = []
    if not accept:
        return result
    for media_range in accept.split(","):
        media_type, *parts = media_range.split(";")
        media_type = media_type.strip()
        if not media_type:
            continue

        q = 1.0
        for part in parts:
            (key, _, value) = part.partition("=")
            key = key.strip()
            if key == "q":
                try:
                    q = float(value)
                except ValueError:
                    pass
                break
        result.append((media_type, q))
    result.sort(key=itemgetter(1), reverse=True)
    return result


def get_accepted_mimetype(accept_header, choices=None):
    ''







    for mime, q in _parse_accept_header(accept_header):
        if choices:
            if mime in choices:
                return mime
            else:
                continue
        else:
            return mime
    return None


def catch_db_error(f):
    ''

    @functools.wraps(f)
    async def catching(self, *args, **kwargs):
        try:
            r = f(self, *args, **kwargs)
            if inspect.isawaitable(r):
                r = await r
        except SQLAlchemyError:
            self.log.exception("Rolling back session due to database error")
            self.db.rollback()
        else:
            return r

    return catching


def get_browser_protocol(request):
    ''











    headers = request.headers

    forwarded_header = headers.get("Forwarded")
    if forwarded_header:
        first_forwarded = forwarded_header.split(",", 1)[0].strip()
        fields = {}
        forwarded_dict = {}
        for field in first_forwarded.split(";"):
            key, _, value = field.partition("=")
            fields[key.strip().lower()] = value.strip()
        if "proto" in fields and fields["proto"].lower() in {"http", "https"}:
            return fields["proto"].lower()
        else:
            app_log.warning(
                f"Forwarded header present without protocol: {forwarded_header}"
            )


    proto_header = headers.get("X-Scheme", headers.get("X-Forwarded-Proto", None))
    if proto_header:
        proto_header = proto_header.split(",")[0].strip().lower()
        if proto_header in {"http", "https"}:
            return proto_header


    return request.protocol




_dns_safe = set(string.ascii_letters + string.digits + '-.')

_dns_needs_replace = _dns_safe | {"%"}


@lru_cache
def _dns_quote(name):
    ''







    label = quote(name, safe="").lower()




    unique_chars = set(label)
    for c in unique_chars:
        if c not in _dns_needs_replace:
            label = label.replace(c, f"%{ord(c):x}")





    label = label.replace("%", "_")
    return label


def subdomain_hook_legacy(name, domain, kind):
    ''




    if kind == "user":

        return f"{_dns_quote(name)}.{domain}"
    elif kind == "service":
        return f"services.{domain}"
    else:
        raise ValueError(f"kind must be 'service' or 'user', not {kind!r}")



_strict_dns_safe = set(string.ascii_lowercase) | set(string.digits)


def _trim_and_hash(name):
    ''











    name_hash = hashlib.sha256(name.encode('utf8')).hexdigest()[:7]

    safe_chars = [c for c in name.lower() if c in _strict_dns_safe]
    name_stub = ''.join(safe_chars[:8])




    if not name_stub:
        name_stub = "x"
    return f"u-{name_stub}--{name_hash}"





_dns_re = re.compile(r'^[a-z0-9-]{1,63}$', flags=re.IGNORECASE)


def _is_dns_safe(label, max_length=63):

    if label.isnumeric():
        return False

    if not 0 < len(label) <= max_length:
        return False

    if label.startswith('-') or label.endswith('-'):
        return False
    return bool(_dns_re.match(label))


def _strict_dns_safe_encode(name, max_length=63):
    ''










    if '--' in name:
        return _trim_and_hash(name)


    if _is_dns_safe(name, max_length=max_length):
        return name


    try:
        idna_name = idna.encode(name).decode("ascii")
    except ValueError:
        idna_name = None

    if idna_name and idna_name != name and _is_dns_safe(idna_name):
        return idna_name


    return _trim_and_hash(name)


def subdomain_hook_idna(name, domain, kind):
    ''







    safe_name = _strict_dns_safe_encode(name)
    if kind == 'user':


        suffix = ""
    else:
        suffix = f"--{kind}"
    return f"{safe_name}{suffix}.{domain}"



def recursive_update(target, new):
    ''




    for k, v in new.items():
        if isinstance(v, dict):
            if k not in target:
                target[k] = {}
            recursive_update(target[k], v)

        elif v is None:
            target.pop(k, None)

        else:
            target[k] = v


def fmt_ip_url(ip):
    ''



    if ":" in ip:
        return f"[{ip}]"
    return ip


def format_exception(exc, *, only_jupyterhub=False):
    ''


    default_message = None if only_jupyterhub else str(exc)
    return getattr(exc, "jupyterhub_message", default_message), getattr(
        exc, "jupyterhub_html_message", None
    )
