''



import asyncio
import functools
import json
import math
import random
import re
import time
import uuid
import warnings
from datetime import timedelta
from http.client import responses
from urllib.parse import parse_qs, parse_qsl, urlencode, urlparse, urlunparse

from jinja2 import TemplateNotFound
from sqlalchemy.exc import SQLAlchemyError
from tornado import gen, web
from tornado.httputil import HTTPHeaders, url_concat
from tornado.ioloop import IOLoop
from tornado.log import app_log
from tornado.web import RequestHandler, addslash

from .. import __version__, orm, roles, scopes
from .._xsrf_utils import (
    _anonymous_xsrf_id,
    _set_xsrf_cookie,
    check_xsrf_cookie,
    get_xsrf_token,
)
from ..metrics import (
    PROXY_ADD_DURATION_SECONDS,
    PROXY_DELETE_DURATION_SECONDS,
    RUNNING_SERVERS,
    SERVER_POLL_DURATION_SECONDS,
    SERVER_SPAWN_DURATION_SECONDS,
    SERVER_STOP_DURATION_SECONDS,
    TOTAL_USERS,
    ProxyDeleteStatus,
    ServerPollStatus,
    ServerSpawnStatus,
    ServerStopStatus,
)
from ..objects import Server
from ..spawner import LocalProcessSpawner
from ..user import User
from ..utils import (
    AnyTimeoutError,
    get_accepted_mimetype,
    get_browser_protocol,
    maybe_future,
    url_escape_path,
    url_path_join,
    utcnow,
)


auth_header_pat = re.compile(r'^(?:token|bearer)\s+([^\s]+)$', flags=re.IGNORECASE)


reasons = {
    'timeout': "Failed to reach your server."
    "  Please try again later."
    "  Contact admin if the issue persists.",
    'error': "Failed to start your server on the last attempt.  "
    "  Please contact admin if the issue persists.",
}


SESSION_COOKIE_NAME = 'jupyterhub-session-id'


class BaseHandler(RequestHandler):
    ''




    _accept_cookie_auth = True
    _accept_token_auth = False

    async def prepare(self):
        ''










        self.expanded_scopes = set()
        try:
            await self.get_current_user()
        except Exception as e:


            self._jupyterhub_user = None
            self.log.exception("Failed to get current user")
            if isinstance(e, SQLAlchemyError):
                self.log.error("Rolling back session due to database error")
                self.db.rollback()
        self._resolve_roles_and_scopes()
        await maybe_future(super().prepare())


        if (
            self.request.method not in self._xsrf_safe_methods
            and self.application.settings.get("xsrf_cookies")
        ):
            self.check_xsrf_cookie()

    @property
    def log(self):
        ''
        return self.settings.get('log', app_log)

    @property
    def config(self):
        return self.settings.get('config', None)

    @property
    def base_url(self):
        return self.settings.get('base_url', '/')

    @property
    def default_url(self):
        return self.settings.get('default_url', '')

    @property
    def version_hash(self):
        return self.settings.get('version_hash', '')

    @property
    def subdomain_host(self):
        return self.settings.get('subdomain_host', '')

    @property
    def allow_named_servers(self):
        return self.settings.get('allow_named_servers', False)

    @property
    def named_server_limit_per_user(self):
        return self.settings.get('named_server_limit_per_user', 0)

    @property
    def domain(self):
        return self.settings['domain']

    @property
    def public_url(self):
        return self.settings['public_url']

    @property
    def db(self):
        return self.settings['db']

    @property
    def users(self):
        return self.settings.setdefault('users', {})

    @property
    def services(self):
        return self.settings.setdefault('services', {})

    @property
    def hub(self):
        return self.settings['hub']

    @property
    def app(self):
        return self.settings['app']

    @property
    def proxy(self):
        return self.settings['proxy']

    @property
    def statsd(self):
        return self.settings['statsd']

    @property
    def authenticator(self):
        return self.settings.get('authenticator', None)

    @property
    def oauth_provider(self):
        return self.settings['oauth_provider']

    @property
    def eventlog(self):
        return self.settings['eventlog']

    def finish(self, *args, **kwargs):
        ''
        if self.db.dirty:
            self.log.warning("Rolling back dirty objects %s", self.db.dirty)
            self.db.rollback()
        super().finish(*args, **kwargs)





    @property
    def csp_report_uri(self):
        return self.settings.get(
            'csp_report_uri', url_path_join(self.hub.base_url, 'security/csp-report')
        )

    @property
    def content_security_policy(self):
        ''







        return '; '.join(
            ["frame-ancestors 'none'", "report-uri " + self.csp_report_uri]
        )

    def get_content_type(self):
        return 'text/html'

    def set_default_headers(self):
        ''





        headers = HTTPHeaders(self.settings.get('headers', {}))
        headers.setdefault("X-JupyterHub-Version", __version__)

        for header_name, header_content in headers.items():
            self.set_header(header_name, header_content)

        if 'Access-Control-Allow-Headers' not in headers:
            self.set_header(
                'Access-Control-Allow-Headers', 'accept, content-type, authorization'
            )
        if 'Content-Security-Policy' not in headers:
            self.set_header('Content-Security-Policy', self.content_security_policy)
        self.set_header('Content-Type', self.get_content_type())





    _xsrf_safe_methods = {"GET", "HEAD", "OPTIONS"}

    @property
    def _xsrf_token_id(self):
        ''














        session_id = self.get_session_cookie()
        if self.current_user:
            if isinstance(self.current_user, User):
                user_id = self.current_user.cookie_id
                if not session_id:

                    self.log.warning(
                        "session id not set for %s, setting a new one",
                        self.current_user.name,
                    )
                    self.set_session_cookie()
                    session_id = self._session_id
            else:


                user_id = session_id = ""
        else:

            user_id = _anonymous_xsrf_id(self)
        xsrf_id = f"{session_id}:{user_id}".encode("utf8", "replace")
        return xsrf_id

    @property
    def xsrf_token(self):
        ''





        return get_xsrf_token(self, cookie_path=self.hub.base_url)

    def check_xsrf_cookie(self):
        ''



        if not hasattr(self, "_jupyterhub_user"):



            return None
        return check_xsrf_cookie(self)

    @property
    def admin_users(self):
        return self.settings.setdefault('admin_users', set())

    @property
    def cookie_max_age_days(self):
        return self.settings.get('cookie_max_age_days', None)

    @property
    def redirect_to_server(self):
        return self.settings.get('redirect_to_server', True)

    @property
    def authenticate_prometheus(self):
        return self.settings.get('authenticate_prometheus', True)

    async def get_current_user_named_server_limit(self):
        ''


        named_server_limit_per_user = self.named_server_limit_per_user

        if callable(named_server_limit_per_user):
            return await maybe_future(named_server_limit_per_user(self))

        return named_server_limit_per_user

    def get_auth_token(self):
        ''
        auth_header = self.request.headers.get('Authorization', '')
        match = auth_header_pat.match(auth_header)
        if not match:
            return None
        return match.group(1)

    def _record_activity(self, obj, timestamp=None):
        ''










        if timestamp is None:
            timestamp = utcnow(with_tz=False)
        resolution = self.settings.get("activity_resolution", 0)
        if not obj.last_activity or resolution == 0:
            self.log.debug("Recording first activity for %s", obj)
            obj.last_activity = timestamp
            return True
        if (timestamp - obj.last_activity).total_seconds() > resolution:



            obj.last_activity = timestamp
            return True
        return False

    async def refresh_auth(self, user, force=False):
        ''












        refresh_age = self.authenticator.auth_refresh_age
        if not refresh_age:
            return user
        now = time.monotonic()
        if (
            not force
            and user._auth_refreshed
            and (now - user._auth_refreshed < refresh_age)
        ):

            return user


        if not hasattr(self, '_refreshed_users'):
            self._refreshed_users = set()
        if user.name in self._refreshed_users:

            return user
        self._refreshed_users.add(user.name)

        self.log.debug("Refreshing auth for %s", user.name)
        auth_info = await self.authenticator.refresh_user(user, self)

        if not auth_info:
            self.log.warning(
                "User %s has stale auth info. Login is required to refresh.", user.name
            )
            return

        user._auth_refreshed = now

        if auth_info == True:


            return user


        auth_info['name'] = user.name

        if 'auth_state' not in auth_info:


            auth_info['auth_state'] = await user.get_auth_state()
        return await self.auth_to_user(auth_info, user)

    @functools.lru_cache
    def get_token(self):
        ''
        token = self.get_auth_token()
        if token is None:
            return None
        orm_token = orm.APIToken.find(self.db, token)
        return orm_token

    def get_current_user_token(self):
        ''

        orm_token = self.get_token()
        if orm_token is None:
            return None
        now = utcnow(with_tz=False)
        recorded = self._record_activity(orm_token, now)
        if orm_token.user:



            if not orm_token.note or not orm_token.note.startswith("Server at "):
                recorded = self._record_activity(orm_token.user, now) or recorded
        if recorded:
            self.db.commit()



        self._token_authenticated = True

        if orm_token.service:
            return orm_token.service

        return self._user_from_orm(orm_token.user)

    def _user_for_cookie(self, cookie_name, cookie_value=None):
        ''
        cookie_id = self.get_secure_cookie(
            cookie_name, cookie_value, max_age_days=self.cookie_max_age_days
        )

        def clear():
            self.clear_cookie(cookie_name, path=self.hub.base_url)

        if cookie_id is None:
            if self.get_cookie(cookie_name):
                self.log.warning("Invalid or expired cookie token")
                clear()
            return
        cookie_id = cookie_id.decode('utf8', 'replace')
        u = self.db.query(orm.User).filter(orm.User.cookie_id == cookie_id).first()
        user = self._user_from_orm(u)
        if user is None:
            self.log.warning("Invalid cookie token")

            clear()
            return


        if self._record_activity(user):
            self.db.commit()
        return user

    def _user_from_orm(self, orm_user):
        ''
        if orm_user is None:
            return
        return self.users[orm_user]

    def get_current_user_cookie(self):
        ''
        user = self._user_for_cookie(self.hub.cookie_name)
        if user and not self.get_session_cookie():

            self.log.debug("Setting new session id for %s", user.name)
            self.set_session_cookie()
        return user

    async def get_current_user(self):
        ''
        if not hasattr(self, '_jupyterhub_user'):
            user = None
            try:
                if self._accept_token_auth:
                    user = self.get_current_user_token()
                if user is None and self._accept_cookie_auth:
                    user = self.get_current_user_cookie()
                if user and isinstance(user, User):
                    user = await self.refresh_auth(user)
                self._jupyterhub_user = user
            except Exception:

                self._jupyterhub_user = None

                raise
        return self._jupyterhub_user

    def _resolve_roles_and_scopes(self):
        self.expanded_scopes = set()
        if self.current_user:
            orm_token = self.get_token()
            if orm_token:
                self.expanded_scopes = scopes.get_scopes_for(orm_token)
            else:
                self.expanded_scopes = scopes.get_scopes_for(self.current_user)
        self.parsed_scopes = scopes.parse_scopes(self.expanded_scopes)

    @functools.lru_cache
    def get_scope_filter(self, req_scope):
        ''





        def no_access(orm_resource, kind):
            return False

        if req_scope not in self.parsed_scopes:
            return no_access

        sub_scope = self.parsed_scopes[req_scope]

        return functools.partial(scopes.check_scope_filter, sub_scope)

    def has_scope(self, scope):
        ''
        return scopes.has_scope(scope, self.parsed_scopes, db=self.db)

    @property
    def current_user(self):
        ''



        if not hasattr(self, '_jupyterhub_user'):
            raise RuntimeError("Must call async get_current_user first!")
        return self._jupyterhub_user

    def find_user(self, name):
        ''



        orm_user = orm.User.find(db=self.db, name=name)
        return self._user_from_orm(orm_user)

    def user_from_username(self, username):
        ''
        user = self.find_user(username)
        if user is None:

            u = orm.User(name=username)
            self.db.add(u)
            roles.assign_default_roles(self.db, entity=u)
            TOTAL_USERS.inc()
            self.db.commit()
            user = self._user_from_orm(u)
        return user

    def clear_cookie(self, cookie_name, **kwargs):
        ''



        if cookie_name.startswith("__Host-"):
            kwargs["path"] = "/"
            kwargs["secure"] = True
        return super().clear_cookie(cookie_name, **kwargs)

    def clear_login_cookie(self, name=None):
        kwargs = {}
        user = self.get_current_user_cookie()
        session_id = self.get_session_cookie()
        if session_id:

            session_cookie_kwargs = {}
            session_cookie_kwargs.update(kwargs)
            if self.subdomain_host:
                session_cookie_kwargs['domain'] = self.domain

            self.clear_cookie(
                SESSION_COOKIE_NAME, path=self.base_url, **session_cookie_kwargs
            )

            if user:



                count = 0
                for access_token in self.db.query(orm.APIToken).filter_by(
                    user_id=user.id, session_id=session_id
                ):
                    self.db.delete(access_token)
                    count += 1
                if count:
                    self.log.debug("Deleted %s access tokens for %s", count, user.name)
                    self.db.commit()


        self.clear_cookie(self.hub.cookie_name, path=self.hub.base_url, **kwargs)



        self.clear_cookie(
            'jupyterhub-services',
            path=url_path_join(self.base_url, 'services'),
            **kwargs,
        )

        clear_xsrf_cookie_kwargs = {
            key: value
            for key, value in self.settings.get('xsrf_cookie_kwargs', {}).items()
            if key in {"path", "domain"}
        }

        self.clear_cookie(
            '_xsrf',
            **clear_xsrf_cookie_kwargs,
        )

    def _set_cookie(self, key, value, encrypted=True, **overrides):
        ''






        kwargs = {'httponly': True}
        public_url = self.settings.get("public_url")
        if public_url:
            if public_url.scheme == 'https':
                kwargs['secure'] = True
        else:
            if self.request.protocol == 'https':
                kwargs['secure'] = True

        kwargs.update(self.settings.get('cookie_options', {}))
        kwargs.update(overrides)

        if key.startswith("__Host-"):

            kwargs["path"] = "/"
            kwargs["secure"] = True

        if encrypted:
            set_cookie = self.set_secure_cookie
        else:
            set_cookie = self.set_cookie

        self.log.debug("Setting cookie %s: %s", key, kwargs)
        set_cookie(key, value, **kwargs)

    def _set_user_cookie(self, user, server):
        self.log.debug("Setting cookie for %s: %s", user.name, server.cookie_name)
        self._set_cookie(
            server.cookie_name, user.cookie_id, encrypted=True, path=server.base_url
        )

    def get_session_cookie(self):
        ''



        if hasattr(self, "_session_id"):
            return self._session_id
        return self.get_cookie(SESSION_COOKIE_NAME, None)

    def set_session_cookie(self):
        ''






        if not hasattr(self, "_session_id"):
            self._session_id = uuid.uuid4().hex
        session_id = self._session_id



        kwargs = {}
        if self.subdomain_host:
            kwargs['domain'] = self.domain
        self._set_cookie(
            SESSION_COOKIE_NAME,
            session_id,
            encrypted=False,
            path=self.base_url,
            **kwargs,
        )
        return session_id

    def set_service_cookie(self, user):
        ''
        warnings.warn(
            "set_service_cookie is deprecated in JupyterHub 2.0. Not setting jupyterhub-services cookie.",
            DeprecationWarning,
            stacklevel=2,
        )

    def set_hub_cookie(self, user):
        ''
        self._set_user_cookie(user, self.hub)

    def set_login_cookie(self, user):
        ''
        if self.subdomain_host and not self.request.host.startswith(self.domain):
            self.log.warning(
                "Possibly setting cookie on wrong domain: %s != %s",
                self.request.host,
                self.domain,
            )

        if not self.get_session_cookie():
            self.set_session_cookie()


        cookie_user = self.get_current_user_cookie()
        if cookie_user is None or cookie_user.id != user.id:
            if cookie_user:
                self.log.info(f"User {cookie_user.name} is logging in as {user.name}")
            self.set_hub_cookie(user)



        self._jupyterhub_user = user
        _set_xsrf_cookie(
            self, self._xsrf_token_id, cookie_path=self.hub.base_url, authenticated=True
        )

    def authenticate(self, data):
        return maybe_future(self.authenticator.get_authenticated_user(self, data))

    def _validate_next_url(self, next_url):
        ''







        next_url = next_url.replace('\\', '%5C')
        public_url = self.settings.get("public_url")
        if public_url:
            proto = public_url.scheme
            host = public_url.netloc
        else:

            proto = get_browser_protocol(self.request)
            host = self.request.host

        if next_url.startswith("///"):




            next_url = "//" + next_url.lstrip("/")
        parsed_next_url = urlparse(next_url)

        if (next_url + '/').startswith(
            (
                f'{proto}://{host}/',
                f'//{host}/',
            )
        ) or (
            self.subdomain_host
            and parsed_next_url.netloc
            and ("." + parsed_next_url.netloc).endswith(
                "." + urlparse(self.subdomain_host).netloc
            )
        ):


            next_url = parsed_next_url.path

            next_url = "/" + next_url.lstrip("/")
            if parsed_next_url.query:
                next_url = next_url + '?' + parsed_next_url.query
            if parsed_next_url.fragment:
                next_url = next_url + '#' + parsed_next_url.fragment
            parsed_next_url = urlparse(next_url)


        if next_url and (parsed_next_url.netloc or not next_url.startswith('/')):
            self.log.warning("Disallowing redirect outside JupyterHub: %r", next_url)
            next_url = ''

        return next_url

    def get_next_url(self, user=None, default=None):
        ''






        next_url = self.get_argument('next', default='')
        next_url = self._validate_next_url(next_url)


        if next_url:
            next_url_from_param = True
        else:
            next_url_from_param = False

        if not next_url:

            if default:
                next_url = default
            else:

                if callable(self.default_url):
                    next_url = self.default_url(self)
                else:
                    next_url = self.default_url

        if not next_url:



            if user and self.redirect_to_server:
                if user.spawner.active:

                    next_url = user.url
                else:

                    next_url = url_path_join(self.hub.base_url, 'spawn')
            else:
                next_url = url_path_join(self.hub.base_url, 'home')

        if not next_url_from_param:


            next_url = self.append_query_parameters(next_url, exclude=['next', '_xsrf'])
        return next_url

    def append_query_parameters(self, url, exclude=None):
        ''


















        if exclude is None:
            exclude = ['next']
        if self.request.query:
            query_string = [
                param
                for param in parse_qsl(self.request.query)
                if param[0] not in exclude
            ]
            if query_string:
                url = url_concat(url, query_string)
        return url

    async def auth_to_user(self, authenticated, user=None):
        ''







        if isinstance(authenticated, str):
            authenticated = {'name': authenticated}
        username = authenticated['name']
        auth_state = authenticated.get('auth_state')
        admin = authenticated.get('admin')
        refreshing = user is not None

        if user and username != user.name:
            raise ValueError(f"Username doesn't match! {username} != {user.name}")

        if user is None:
            user = self.find_user(username)
            new_user = user is None
            if new_user:
                user = self.user_from_username(username)
                await maybe_future(self.authenticator.add_user(user))

        if admin is not None and admin != user.admin:
            user.admin = admin


        roles.assign_default_roles(self.db, entity=user)


        if self.authenticator.manage_groups:
            if "groups" not in authenticated:



                auth_cls = self.authenticator.__class__.__name__
                raise ValueError(
                    f"Authenticator.manage_groups is enabled, but auth_model for {username} specifies no groups."
                    f" Does {auth_cls} support manage_groups=True?"
                )
            group_names = authenticated["groups"]
            if group_names is not None:
                user.sync_groups(group_names)

        if self.authenticator.manage_roles:
            auth_roles = authenticated.get("roles")
            if auth_roles is not None:
                user.sync_roles(auth_roles)



        if not self.authenticator.enable_auth_state:

            auth_state = None

        await user.save_auth_state(auth_state)

        return user

    async def login_user(self, data=None):
        ''
        auth_timer = self.statsd.timer('login.authenticate').start()
        authenticated = await self.authenticate(data)
        auth_timer.stop(send=False)

        if authenticated:
            user = await self.auth_to_user(authenticated)
            self.set_login_cookie(user)
            self.statsd.incr('login.success')
            self.statsd.timing('login.authenticate.success', auth_timer.ms)

            self.log.info("User logged in: %s", user.name)
            user._auth_refreshed = time.monotonic()
            return user
        else:
            self.statsd.incr('login.failure')
            self.statsd.timing('login.authenticate.failure', auth_timer.ms)
            log_username = username = (data or {}).get('username', 'unknown user')

            if len(username) > 32:
                log_username = f"{username[:16]}...({len(username)} chars)"
            self.log.warning("Failed login for %r", log_username)





    @property
    def slow_spawn_timeout(self):
        return self.settings.get('slow_spawn_timeout', 10)

    @property
    def slow_stop_timeout(self):
        return self.settings.get('slow_stop_timeout', 10)

    @property
    def spawner_class(self):
        return self.settings.get('spawner_class', LocalProcessSpawner)

    @property
    def concurrent_spawn_limit(self):
        return self.settings.get('concurrent_spawn_limit', 0)

    @property
    def active_server_limit(self):
        return self.settings.get('active_server_limit', 0)

    async def spawn_single_user(self, user, server_name='', options=None):

        if self.authenticator.refresh_pre_spawn:
            auth_user = await self.refresh_auth(user, force=True)
            if auth_user is None:
                raise web.HTTPError(
                    403, "auth has expired for %s, login again", user.name
                )

        spawn_start_time = time.perf_counter()
        self.extra_error_html = self.spawn_home_error

        user_server_name = user.name

        if server_name:
            if '/' in server_name:
                error_message = (
                    f"Invalid server_name (may not contain '/'): {server_name}"
                )
                self.log.error(error_message)
                raise web.HTTPError(400, error_message)
            user_server_name = f'{user.name}:{server_name}'

        if server_name in user.spawners and user.spawners[server_name].pending:
            pending = user.spawners[server_name].pending
            SERVER_SPAWN_DURATION_SECONDS.labels(
                status=ServerSpawnStatus.already_pending
            ).observe(time.perf_counter() - spawn_start_time)
            raise RuntimeError(f"{user_server_name} pending {pending}")





        active_counts = self.users.count_active_users()
        spawn_pending_count = (
            active_counts['spawn_pending'] + active_counts['proxy_pending']
        )
        active_count = active_counts['active']
        RUNNING_SERVERS.set(active_count)

        concurrent_spawn_limit = self.concurrent_spawn_limit
        active_server_limit = self.active_server_limit

        if concurrent_spawn_limit and spawn_pending_count >= concurrent_spawn_limit:
            SERVER_SPAWN_DURATION_SECONDS.labels(
                status=ServerSpawnStatus.throttled
            ).observe(time.perf_counter() - spawn_start_time)



            retry_range = self.settings['spawn_throttle_retry_range']
            retry_time = int(random.uniform(*retry_range))


            if retry_time <= 90:

                delay = math.ceil(retry_time / 10.0)
                human_retry_time = f"{delay}0 seconds"
            else:

                delay = round(retry_time / 60.0)
                human_retry_time = f"{delay} minutes"

            self.log.warning(
                '%s pending spawns, throttling. Suggested retry in %s seconds.',
                spawn_pending_count,
                retry_time,
            )
            err = web.HTTPError(
                429,
                f"Too many users trying to log in right now. Try again in {human_retry_time}.",
            )



            err.headers = {'Retry-After': retry_time}
            raise err

        if active_server_limit and active_count >= active_server_limit:
            self.log.info('%s servers active, no space available', active_count)
            SERVER_SPAWN_DURATION_SECONDS.labels(
                status=ServerSpawnStatus.too_many_users
            ).observe(time.perf_counter() - spawn_start_time)
            raise web.HTTPError(
                429, "Active user limit exceeded. Try again in a few minutes."
            )

        tic = IOLoop.current().time()

        self.log.debug("Initiating spawn for %s", user_server_name)

        spawn_future = user.spawn(server_name, options, handler=self)

        self.log.debug(
            "%i%s concurrent spawns",
            spawn_pending_count,
            f'/{concurrent_spawn_limit}' if concurrent_spawn_limit else '',
        )
        self.log.debug(
            "%i%s active servers",
            active_count,
            f'/{active_server_limit}' if active_server_limit else '',
        )

        spawner = user.spawners[server_name]


        spawner._spawn_pending = True

        async def finish_user_spawn():
            ''





            await spawn_future
            toc = IOLoop.current().time()
            self.log.info(
                "User %s took %.3f seconds to start", user_server_name, toc - tic
            )
            self.statsd.timing('spawner.success', (toc - tic) * 1000)
            SERVER_SPAWN_DURATION_SECONDS.labels(
                status=ServerSpawnStatus.success
            ).observe(time.perf_counter() - spawn_start_time)
            self.eventlog.emit(
                schema_id='https://schema.jupyter.org/jupyterhub/events/server-action',
                data={
                    'action': 'start',
                    'username': user.name,
                    'servername': server_name,
                },
            )
            proxy_add_start_time = time.perf_counter()
            spawner._proxy_pending = True
            try:
                await self.proxy.add_user(user, server_name)

                PROXY_ADD_DURATION_SECONDS.labels(status='success').observe(
                    time.perf_counter() - proxy_add_start_time
                )
                RUNNING_SERVERS.inc()
            except Exception:
                self.log.exception("Failed to add %s to proxy!", user_server_name)
                self.log.error(
                    "Stopping %s to avoid inconsistent state", user_server_name
                )
                await user.stop(server_name)
                PROXY_ADD_DURATION_SECONDS.labels(status='failure').observe(
                    time.perf_counter() - proxy_add_start_time
                )
            else:
                spawner.add_poll_callback(self.user_stopped, user, server_name)
            finally:
                spawner._proxy_pending = False



        finish_spawn_future = spawner._spawn_future = maybe_future(finish_user_spawn())

        def _clear_spawn_future(f):



            if f.cancelled() or f.exception() is None:
                spawner._spawn_future = None

            spawner._spawn_pending = False

        finish_spawn_future.add_done_callback(_clear_spawn_future)




        def _track_failure_count(f):
            if f.cancelled() or f.exception() is None:

                self.settings['failure_count'] = 0
                return

            SERVER_SPAWN_DURATION_SECONDS.labels(
                status=ServerSpawnStatus.failure
            ).observe(time.perf_counter() - spawn_start_time)
            self.settings.setdefault('failure_count', 0)
            self.settings['failure_count'] += 1
            failure_count = self.settings['failure_count']
            failure_limit = spawner.consecutive_failure_limit
            if failure_limit and 1 < failure_count < failure_limit:
                self.log.warning(
                    "%i consecutive spawns failed.  "
                    "Hub will exit if failure count reaches %i before succeeding",
                    failure_count,
                    failure_limit,
                )
            if failure_limit and failure_count >= failure_limit:
                self.log.critical(
                    "Aborting due to %i consecutive spawn failures", failure_count
                )



                def abort():
                    raise SystemExit(1)

                IOLoop.current().call_later(2, abort)

        finish_spawn_future.add_done_callback(_track_failure_count)

        try:
            await gen.with_timeout(
                timedelta(seconds=self.slow_spawn_timeout), finish_spawn_future
            )
        except AnyTimeoutError:


            if spawner._spawn_pending and not spawner._waiting_for_response:


                if self.slow_spawn_timeout > 0:


                    self.log.warning(
                        "User %s is slow to start (timeout=%s)",
                        user_server_name,
                        self.slow_spawn_timeout,
                    )
                return



            poll_start_time = time.perf_counter()
            status = await spawner.poll()
            SERVER_POLL_DURATION_SECONDS.labels(
                status=ServerPollStatus.from_status(status)
            ).observe(time.perf_counter() - poll_start_time)

            if status is not None:
                toc = IOLoop.current().time()
                self.statsd.timing('spawner.failure', (toc - tic) * 1000)
                SERVER_SPAWN_DURATION_SECONDS.labels(
                    status=ServerSpawnStatus.failure
                ).observe(time.perf_counter() - spawn_start_time)




                try:
                    await asyncio.wait_for(
                        asyncio.shield(finish_spawn_future), timeout=1
                    )
                except TimeoutError:
                    pass

                if finish_spawn_future.exception():

                    await finish_spawn_future

                raise web.HTTPError(
                    500,
                    f"Spawner failed to start [status={status}]. The logs for {spawner._log_name} may contain details.",
                )

            if spawner._waiting_for_response:



                self.log.warning(
                    "User %s is slow to become responsive (timeout=%s)",
                    user_server_name,
                    self.slow_spawn_timeout,
                )
                self.log.debug(
                    "Expecting server for %s at: %s",
                    user_server_name,
                    spawner.server.url,
                )
            if spawner._proxy_pending:


                self.log.warning(
                    "User %s is slow to be added to the proxy (timeout=%s)",
                    user_server_name,
                    self.slow_spawn_timeout,
                )

    async def user_stopped(self, user, server_name):
        ''
        spawner = user.spawners[server_name]

        poll_start_time = time.perf_counter()
        status = await spawner.poll()
        SERVER_POLL_DURATION_SECONDS.labels(
            status=ServerPollStatus.from_status(status)
        ).observe(time.perf_counter() - poll_start_time)

        if status is None:
            status = 'unknown'

        self.log.warning(
            "User %s server stopped, with exit code: %s", user.name, status
        )
        proxy_deletion_start_time = time.perf_counter()
        try:
            await self.proxy.delete_user(user, server_name)
            PROXY_DELETE_DURATION_SECONDS.labels(
                status=ProxyDeleteStatus.success
            ).observe(time.perf_counter() - proxy_deletion_start_time)
        except Exception:
            PROXY_DELETE_DURATION_SECONDS.labels(
                status=ProxyDeleteStatus.failure
            ).observe(time.perf_counter() - proxy_deletion_start_time)
            raise

        await user.stop(server_name)

    async def stop_single_user(self, user, server_name=''):
        if server_name not in user.spawners:
            raise KeyError("User %s has no such spawner %r", user.name, server_name)
        spawner = user.spawners[server_name]
        if spawner.pending:
            raise RuntimeError(f"{spawner._log_name} pending {spawner.pending}")

        if self.authenticator.refresh_pre_stop:
            auth_user = await self.refresh_auth(user, force=True)
            if auth_user is None:
                if (
                    self.current_user.kind == "user"
                    and self.current_user.name == user.name
                ):
                    raise web.HTTPError(
                        403, "auth has expired for %s, login again", user.name
                    )
                else:
                    self.log.warning(
                        "User %s may have stale auth info. Stopping anyway.", user.name
                    )



        spawner._stop_pending = True

        async def stop():
            ''





            tic = time.perf_counter()
            try:
                await self.proxy.delete_user(user, server_name)
                PROXY_DELETE_DURATION_SECONDS.labels(
                    status=ProxyDeleteStatus.success
                ).observe(time.perf_counter() - tic)

                await user.stop(server_name)
                toc = time.perf_counter()
                self.log.info(
                    "User %s server took %.3f seconds to stop", user.name, toc - tic
                )
                self.statsd.timing('spawner.stop', (toc - tic) * 1000)
                SERVER_STOP_DURATION_SECONDS.labels(
                    status=ServerStopStatus.success
                ).observe(toc - tic)
                self.eventlog.emit(
                    schema_id='https://schema.jupyter.org/jupyterhub/events/server-action',
                    data={
                        'action': 'stop',
                        'username': user.name,
                        'servername': server_name,
                    },
                )
            except Exception:
                PROXY_DELETE_DURATION_SECONDS.labels(
                    status=ProxyDeleteStatus.failure
                ).observe(time.perf_counter() - tic)
                SERVER_STOP_DURATION_SECONDS.labels(
                    status=ServerStopStatus.failure
                ).observe(time.perf_counter() - tic)
            finally:
                spawner._stop_future = None
                spawner._stop_pending = False

        future = spawner._stop_future = asyncio.ensure_future(stop())

        try:
            await gen.with_timeout(timedelta(seconds=self.slow_stop_timeout), future)
        except AnyTimeoutError:

            self.log.warning(
                "User %s:%s server is slow to stop (timeout=%s)",
                user.name,
                server_name,
                self.slow_stop_timeout,
            )


        return future





    @property
    def spawn_home_error(self):
        ''




        home = url_path_join(self.hub.base_url, 'home')
        return (
            "You can try restarting your server from the "
            f"<a href='{home}'>home page</a>."
        )

    def get_template(self, name, sync=False):
        ''







        if sync:
            key = 'jinja2_env_sync'
        else:
            key = 'jinja2_env'
        return self.settings[key].get_template(name)

    def render_template(self, name, sync=False, **ns):
        ''





        template_ns = {}
        template_ns.update(self.template_namespace)
        template_ns["xsrf_token"] = self.xsrf_token.decode("ascii")
        template_ns.update(ns)
        template = self.get_template(name, sync)
        if sync:
            return template.render(**template_ns)
        else:
            return template.render_async(**template_ns)

    @property
    def template_namespace(self):
        user = self.current_user
        ns = dict(
            base_url=self.hub.base_url,
            prefix=self.base_url,
            user=user,
            login_url=self.settings['login_url'],
            login_service=self.authenticator.login_service,
            logout_url=self.settings['logout_url'],
            static_url=self.static_url,
            version_hash=self.version_hash,
            services=self.get_accessible_services(user),
            parsed_scopes=self.parsed_scopes,
            expanded_scopes=self.expanded_scopes,
            xsrf=self.xsrf_token.decode('ascii'),
        )
        if self.settings['template_vars']:
            for key, value in self.settings['template_vars'].items():
                if callable(value):
                    value = value(user)
                ns[key] = value
        return ns

    def get_accessible_services(self, user):
        accessible_services = []
        if user is None:
            return accessible_services

        for service_name, service in self.services.items():
            if not service.url:
                continue
            if not service.display:
                continue


            service_scopes = {
                "access:services",
                f"access:services!service={service.name}",
            }
            if not service_scopes.intersection(self.expanded_scopes):
                continue

            accessible_services.append(service)
        return accessible_services

    def write_error(self, status_code, **kwargs):
        ''
        exc_info = kwargs.get('exc_info')
        message = ''
        message_html = ''
        exception = None
        status_message = responses.get(status_code, 'Unknown HTTP Error')
        if exc_info:
            exception = exc_info[1]

            try:
                message = exception.log_message % exception.args
            except Exception:
                pass

            message_html = getattr(exception, "jupyterhub_html_message", "")


            reason = getattr(exception, 'reason', '')
            if reason:
                message = reasons.get(reason, reason)


            message = getattr(exception, "jupyterhub_message", message)

        if exception and isinstance(exception, SQLAlchemyError):
            self.log.warning("Rolling back session due to database error %s", exception)
            self.db.rollback()


        ns = dict(
            status_code=status_code,
            status_message=status_message,
            message=message,
            message_html=message_html,
            extra_error_html=getattr(self, 'extra_error_html', ''),
            exception=exception,
        )

        self.set_header('Content-Type', 'text/html')
        if isinstance(exception, web.HTTPError):


            headers = getattr(exception, 'headers', None)
            if headers:
                for key, value in headers.items():
                    self.set_header(key, value)

            self.clear_header('Content-Length')




        try:
            html = self.render_template(f'{status_code}.html', sync=True, **ns)
        except TemplateNotFound:
            self.log.debug("Using default error template for %d", status_code)
            try:
                html = self.render_template('error.html', sync=True, **ns)
            except Exception:

                ns['no_spawner_check'] = True
                html = self.render_template('error.html', sync=True, **ns)

        self.write(html)


class Template404(BaseHandler):
    ''

    async def prepare(self):
        await super().prepare()
        raise web.HTTPError(404)


class PrefixRedirectHandler(BaseHandler):
    ''














    def get(self):
        uri = self.request.uri



        if not uri.endswith('/'):
            uri += '/'
        if uri.startswith(self.base_url):
            path = self.request.uri[len(self.base_url) :]
        else:
            path = self.request.path
        if not path:


            path = '/'

        redirect_url = redirect_path = url_path_join(self.hub.base_url, path)




        public_url = self.settings.get("public_url")
        subdomain_host = self.settings.get("subdomain_host")
        if public_url:
            redirect_url = urlunparse(public_url._replace(path=redirect_path))
        elif subdomain_host:
            redirect_url = url_path_join(subdomain_host, redirect_path)
        self.redirect(redirect_url, permanent=False)


class UserUrlHandler(BaseHandler):
    ''


















    _accept_token_auth = True




    def _record_activity(self, obj, timestamp=None):
        return False

    def _fail_api_request(self, user_name='', server_name=''):
        ''
        self.log.debug(
            "Failing suspected API request to not-running server: %s", self.request.path
        )





        self.set_status(
            424 if not self.app.use_legacy_stopped_server_status_code else 503
        )
        self.set_header("Content-Type", "application/json")

        spawn_url = urlparse(self.request.full_url())._replace(query="")
        spawn_path_parts = [self.hub.base_url, "spawn", user_name]
        if server_name:
            spawn_path_parts.append(server_name)
        spawn_url = urlunparse(
            spawn_url._replace(path=url_path_join(*spawn_path_parts))
        )
        self.write(
            json.dumps(
                {
                    "message": (
                        f"JupyterHub server no longer running at {self.request.path[len(self.hub.base_url) - 1 :]}."
                        f" Restart the server at {spawn_url}"
                    )
                }
            )
        )
        self.finish()




    def non_get(self, user_name, user_path):
        ''




        if (
            user_name
            and user_path
            and self.allow_named_servers
            and self.current_user
            and user_name == self.current_user.name
        ):
            server_name = user_path.lstrip('/').split('/', 1)[0]
            if server_name not in self.current_user.orm_user.orm_spawners:

                server_name = ''
        else:
            server_name = ''

        self._fail_api_request(user_name, server_name)

    post = non_get
    patch = non_get
    delete = non_get

    @web.authenticated
    async def get(self, user_name, user_path):
        if not user_path:
            user_path = '/'
        path_parts = user_path.split("/", 2)
        server_names = [""]
        if len(path_parts) >= 3:

            server_names.append(path_parts[1])

        access_scopes = [
            f"access:servers!server={user_name}/{server_name}"
            for server_name in server_names
        ]
        if not any(self.has_scope(scope) for scope in access_scopes):
            self.log.warning(
                "Not authorizing access to %s. Requires any of [%s], not derived from scopes [%s]",
                self.request.path,
                ", ".join(access_scopes),
                ", ".join(self.expanded_scopes),
            )
            raise web.HTTPError(404, "No access to resources or resources not found")

        current_user = self.current_user
        if user_name != current_user.name:
            user = self.find_user(user_name)
            if user is None:

                raise web.HTTPError(404, f"No such user {user_name}")
            self.log.info(
                f"User {current_user.name} requesting spawn on behalf of {user.name}"
            )
            admin_spawn = True
            should_spawn = True
            redirect_to_self = False
        else:
            user = current_user





        host_info = urlparse(self.request.full_url())
        port = host_info.port
        if not port:
            port = 443 if host_info.scheme == 'https' else 80
        if (
            port != Server.from_url(self.proxy.public_url).connect_port
            and port == self.hub.connect_port
        ):
            self.log.warning(
                """
                Detected possible direct connection to Hub's private ip: %s, bypassing proxy.
                This will result in a redirect loop.
                Make sure to connect to the proxied public URL %s
                """,
                self.request.full_url(),
                self.proxy.public_url,
            )



        server_name = ''
        if self.allow_named_servers:

            server_name = user_path.lstrip('/').split('/', 1)[0]
            if server_name not in user.orm_user.orm_spawners:

                server_name = ''
        else:
            server_name = ''
        escaped_server_name = url_escape_path(server_name)
        spawner = user.spawners[server_name]

        if spawner.ready:

            await self._redirect_to_user_server(user, spawner)
            return



        if get_accepted_mimetype(
            self.request.headers.get('Accept', ''),
            choices=['application/json', 'text/html'],
        ) == 'application/json' or 'api' in user_path.split('/'):
            self._fail_api_request(user_name, server_name)
            return

        pending_url = url_concat(
            url_path_join(
                self.hub.base_url,
                'spawn-pending',
                user.escaped_name,
                escaped_server_name,
            ),
            {'next': self.request.uri},
        )
        if spawner.pending or spawner._failed:

            self.redirect(pending_url, status=303)
            return





        spawn_url = url_concat(
            url_path_join(
                self.hub.base_url, "spawn", user.escaped_name, escaped_server_name
            ),
            {"next": self.request.uri},
        )
        self.set_status(
            424 if not self.app.use_legacy_stopped_server_status_code else 503
        )

        auth_state = await user.get_auth_state()
        html = await self.render_template(
            "not_running.html",
            user=user,
            server_name=server_name,
            spawn_url=spawn_url,
            auth_state=auth_state,
            implicit_spawn_seconds=self.settings.get("implicit_spawn_seconds", 0),
        )
        self.finish(html)

    async def _redirect_to_user_server(self, user, spawner):
        ''







        try:
            redirects = int(self.get_argument('redirects', 0))
        except ValueError:
            self.log.warning(
                "Invalid redirects argument %r", self.get_argument('redirects')
            )
            redirects = 0



        if redirects >= self.settings.get('user_redirect_limit', 4) or (
            redirects >= 2 and spawner._jupyterhub_version != __version__
        ):

            msg = "Redirect loop detected."
            if spawner._jupyterhub_version != __version__:
                msg += (
                    " Notebook has jupyterhub version {singleuser}, but the Hub expects {hub}."
                    " Try installing jupyterhub=={hub} in the user environment"
                    " if you continue to have problems."
                ).format(
                    singleuser=spawner._jupyterhub_version or 'unknown (likely < 0.8)',
                    hub=__version__,
                )
            raise web.HTTPError(500, msg)

        without_prefix = self.request.uri[len(self.hub.base_url) :]
        target = url_path_join(self.base_url, without_prefix)
        if self.subdomain_host:
            target = user.host + target


        if redirects:
            self.log.warning("Redirect loop detected on %s", self.request.uri)

            await asyncio.sleep(min(1 * (2**redirects), 10))

            url_parts = urlparse(target)
            query_parts = parse_qs(url_parts.query)
            query_parts['redirects'] = redirects + 1
            url_parts = url_parts._replace(query=urlencode(query_parts, doseq=True))
            target = urlunparse(url_parts)
        else:





            target = url_concat(target, {'redirects': 1})

        self.redirect(target)
        self.statsd.incr('redirects.user_after_login')


class UserRedirectHandler(BaseHandler):
    ''













    @web.authenticated
    async def get(self, path):




        url = None
        if self.app.user_redirect_hook:
            url = await maybe_future(
                self.app.user_redirect_hook(
                    path, self.request, self.current_user, self.base_url
                )
            )
        if url is None:
            user = self.current_user
            user_url = user.url

            if self.app.default_server_name:
                user_url = url_path_join(user_url, self.app.default_server_name)

            user_url = url_path_join(user_url, path)
            if self.request.query:
                user_url = url_concat(user_url, parse_qsl(self.request.query))

            if self.app.default_server_name:
                url = url_concat(
                    url_path_join(
                        self.hub.base_url,
                        "spawn",
                        user.escaped_name,
                        self.app.default_server_name,
                    ),
                    {"next": user_url},
                )
            else:
                url = url_concat(
                    url_path_join(self.hub.base_url, "spawn", user.escaped_name),
                    {"next": user_url},
                )

        self.redirect(url)


class CSPReportHandler(BaseHandler):
    ''

    @web.authenticated
    def post(self):
        ''
        self.log.warning(
            "Content security violation: %s",
            self.request.body.decode('utf8', 'replace'),
        )

        self.statsd.incr('csp_report')


class AddSlashHandler(BaseHandler):
    ''

    @addslash
    def get(self):
        pass


default_handlers = [
    (r'', AddSlashHandler),
    (r'/user/(?P<user_name>[^/]+)(?P<user_path>/.*)?', UserUrlHandler),
    (r'/user-redirect/(.*)?', UserRedirectHandler),
    (r'/security/csp-report', CSPReportHandler),
]
