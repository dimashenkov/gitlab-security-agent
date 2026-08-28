

import asyncio
import json
import warnings
from collections import defaultdict
from urllib.parse import quote, urlparse, urlunparse

from sqlalchemy import inspect
from tornado import web
from tornado.httputil import urlencode
from tornado.log import app_log

from . import orm, roles, scopes
from ._version import __version__, _check_version
from .crypto import CryptKeeper, EncryptionUnavailable, InvalidToken, decrypt, encrypt
from .metrics import RUNNING_SERVERS, TOTAL_USERS
from .objects import Server
from .spawner import LocalProcessSpawner
from .utils import (
    AnyTimeoutError,
    _strict_dns_safe,
    make_ssl_context,
    maybe_future,
    subdomain_hook_legacy,
    url_escape_path,
    url_path_join,
    utcnow,
)



start_timeout_message = """
Common causes of this timeout, and debugging tips:

1. Everything is working, but it took too long.
   To fix: increase `Spawner.start_timeout` configuration
   to a number of seconds that is enough for spawners to finish starting.
2. The server didn't finish starting,
   or it crashed due to a configuration issue.
   Check the single-user server's logs for hints at what needs fixing.
"""

http_timeout_message = """
Common causes of this timeout, and debugging tips:

1. The server didn't finish starting,
   or it crashed due to a configuration issue.
   Check the single-user server's logs for hints at what needs fixing.
2. The server started, but is not accessible at the specified URL.
   This may be a configuration issue specific to your chosen Spawner.
   Check the single-user server logs and resource to make sure the URL
   is correct and accessible from the Hub.
3. (unlikely) Everything is working, but the server took too long to respond.
   To fix: increase `Spawner.http_timeout` configuration
   to a number of seconds that is enough for servers to become responsive.
"""


class UserDict(dict):
    ''




















    def __init__(self, db_factory, settings):
        self.db_factory = db_factory
        self.settings = settings
        super().__init__()

    @property
    def db(self):
        return self.db_factory()

    def from_orm(self, orm_user):
        return User(orm_user, self.settings)

    def add(self, orm_user):
        ''
        if orm_user.id not in self:
            self[orm_user.id] = self.from_orm(orm_user)
        return self[orm_user.id]

    def __contains__(self, key):
        ''



        if isinstance(key, (User, orm.User)):
            key = key.id
        elif isinstance(key, str):

            for user in self.values():
                if user.name == key:
                    key = user.id
                    break
        return super().__contains__(key)

    def __getitem__(self, key):
        ''






        if isinstance(key, User):
            key = key.id
        elif isinstance(key, str):
            orm_user = self.db.query(orm.User).filter(orm.User.name == key).first()
            if orm_user is None:
                raise KeyError(f"No such user: {key}")
            else:
                key = orm_user.id
        if isinstance(key, orm.User):

            orm_user = key
            if orm_user.id not in self:
                user = self[orm_user.id] = User(orm_user, self.settings)
                return user
            user = super().__getitem__(orm_user.id)
            user.db = self.db
            return user
        elif isinstance(key, int):
            id = key
            if id not in self:
                orm_user = self.db.query(orm.User).filter(orm.User.id == id).first()
                if orm_user is None:
                    raise KeyError(f"No such user: {id}")
                user = self.add(orm_user)
            else:
                user = super().__getitem__(id)
            return user
        else:
            raise KeyError(repr(key))

    def get(self, key, default=None):
        ''







        try:
            return self[key]
        except KeyError:
            return default

    def __delitem__(self, key):
        user = self[key]
        for orm_spawner in user.orm_user._orm_spawners:
            if orm_spawner in self.db:
                self.db.expunge(orm_spawner)
        if user.orm_user in self.db:
            self.db.expunge(user.orm_user)
        super().__delitem__(user.id)

    def delete(self, key):
        ''
        user = self[key]
        user_id = user.id
        self.db.delete(user)
        self.db.commit()

        TOTAL_USERS.dec()
        del self[user_id]

    def count_active_users(self):
        ''



        counts = defaultdict(int)
        for user in self.values():
            for spawner in user.spawners.values():
                pending = spawner.pending
                if pending:
                    counts['pending'] += 1
                    counts[pending + '_pending'] += 1
                if spawner.active:
                    counts['active'] += 1
                if spawner.ready:
                    counts['ready'] += 1

        return counts


class _SpawnerDict(dict):
    def __init__(self, spawner_factory):
        self.spawner_factory = spawner_factory

    def __getitem__(self, key):
        if key not in self:
            self[key] = self.spawner_factory(key)
        return super().__getitem__(key)


class User:
    ''


    db = None
    orm_user = None
    log = app_log
    settings = None
    _auth_refreshed = None

    def __init__(self, orm_user, settings=None, db=None):
        self.db = db or inspect(orm_user).session
        self.settings = settings or {}
        self.orm_user = orm_user

        self.allow_named_servers = self.settings.get('allow_named_servers', False)

        self.base_url = self.prefix = (
            url_path_join(self.settings.get('base_url', '/'), 'user', self.escaped_name)
            + '/'
        )

        self.spawners = _SpawnerDict(self._new_spawner)


        if '' not in self.orm_user.orm_spawners:
            self._new_orm_spawner('')

    @property
    def authenticator(self):
        return self.settings.get('authenticator', None)

    @property
    def spawner_class(self):
        return self.settings.get('spawner_class', LocalProcessSpawner)

    def get_spawner(self, server_name="", replace_failed=False):
        ''






        spawner = self.spawners[server_name]
        if replace_failed and spawner._failed:
            self.log.debug(f"Discarding failed spawner {spawner._log_name}")

            self.spawners.pop(server_name)
            spawner = self.spawners[server_name]
        return spawner

    def sync_groups(self, group_names):
        ''

        current_groups = {g.name for g in self.orm_user.groups}
        new_groups = set(group_names)
        if current_groups == new_groups:

            return


        added_groups = new_groups.difference(current_groups)
        removed_groups = current_groups.difference(group_names)
        if added_groups:
            self.log.info(f"Adding user {self.name} to group(s): {added_groups}")
        if removed_groups:
            self.log.info(f"Removing user {self.name} from group(s): {removed_groups}")

        if group_names:
            groups = (
                self.db.query(orm.Group).filter(orm.Group.name.in_(new_groups)).all()
            )
            existing_groups = {g.name for g in groups}
            for group_name in added_groups:
                if group_name not in existing_groups:

                    self.log.info(
                        f"Creating new group {group_name} for user {self.name}"
                    )
                    group = orm.Group(name=group_name)
                    self.db.add(group)
                    groups.append(group)
            self.orm_user.groups = groups
        else:
            self.orm_user.groups = []
        self.db.commit()

    def sync_roles(self, auth_roles):
        ''
        auth_roles_by_name = {role['name']: role for role in auth_roles}

        current_user_roles = {r.name for r in self.orm_user.roles}
        new_user_roles = set(auth_roles_by_name.keys())

        granted_roles = new_user_roles.difference(current_user_roles)
        stripped_roles = current_user_roles.difference(new_user_roles)

        if granted_roles:
            self.log.info(f"Granting user {self.name} roles(s): {granted_roles}")
        if stripped_roles:
            self.log.info(f"Stripping user {self.name} roles(s): {stripped_roles}")

        existing_granted_roles = {
            r.name
            for r in self.db.query(orm.Role).filter(orm.Role.name.in_(granted_roles))
        }
        created_roles = existing_granted_roles.difference(granted_roles)

        if created_roles:
            self.log.info(f"Creating new roles {created_roles} in the database")

        for role_name in new_user_roles:
            if role_name in created_roles:
                self.log.info(f"Creating new role {role_name}")
            else:
                self.log.debug(f"Updating existing role {role_name}")

            role = auth_roles_by_name[role_name]
            role['managed_by_auth'] = True


            try:
                orm_role = roles.create_role(
                    self.db, role, commit=False, reset_to_defaults=False
                )
            except (
                roles.RoleValueError,
                roles.InvalidNameError,
                scopes.ScopeNotFound,
            ) as e:
                raise web.HTTPError(409, str(e))


            entity_map = {
                'groups': orm.Group,
                'services': orm.Service,
                'users': orm.User,
            }
            for key, Class in entity_map.items():
                if key in role.keys():
                    entities = []
                    not_found_entities = []
                    for entity_name in role[key]:
                        entity = Class.find(self.db, entity_name)
                        if entity is None:
                            not_found_entities.append(entity_name)
                        else:
                            entities.append(entity)
                    setattr(orm_role, key, entities)
                    if not_found_entities:
                        self.log.warning(
                            f'Could not assign the role {role_name} to {key}:'
                            f' {not_found_entities} not found in the database.'
                        )


        for role_name in granted_roles:
            roles.grant_role(
                self.db,
                entity=self.orm_user,
                rolename=role_name,
                commit=False,
                managed=True,
            )


        for role_name in stripped_roles:
            roles.strip_role(
                self.db, entity=self.orm_user, rolename=role_name, commit=False
            )
        managed_stripped_roles = (
            self.db.query(orm.Role)
            .filter(
                orm.Role.name.in_(stripped_roles) & (orm.Role.managed_by_auth == True)
            )
            .all()
        )

        for stripped_role in managed_stripped_roles:
            if (
                not stripped_role.users
                and not stripped_role.services
                and not stripped_role.groups
                and not stripped_role.name in self.settings.get('config_role_names')
            ):
                self.db.delete(stripped_role)

        self.db.commit()

    async def save_auth_state(self, auth_state):
        ''
        if auth_state is None:
            self.encrypted_auth_state = None
        else:
            self.encrypted_auth_state = await encrypt(auth_state)
        self.db.commit()

    async def get_auth_state(self):
        ''
        encrypted = self.encrypted_auth_state
        if encrypted is None:
            return None
        try:
            auth_state = await decrypt(encrypted)
        except (ValueError, InvalidToken, EncryptionUnavailable) as e:
            self.log.warning(
                "Failed to retrieve encrypted auth_state for %s because %s",
                self.name,
                e,
            )
            return

        if auth_state:

            if len(CryptKeeper.instance().keys) > 1:
                await self.save_auth_state(auth_state)
        return auth_state

    async def delete_spawners(self):
        ''



        for name in self.orm_user.orm_spawners.keys():
            await self._delete_spawner(name)

    async def _delete_spawner(self, name_or_spawner):
        ''



        if isinstance(name_or_spawner, str):
            spawner = self.spawners[name_or_spawner]
        else:
            spawner = name_or_spawner

        if spawner.active:
            raise RuntimeError(
                f"Spawner {spawner._log_name} is active and cannot be deleted."
            )
        try:
            await maybe_future(spawner.delete_forever())
        except Exception as e:
            self.log.exception(
                f"Error cleaning up persistent resources on {spawner._log_name}"
            )

    def all_spawners(self, include_default=True):
        ''







        for name, orm_spawner in sorted(self.orm_user.orm_spawners.items()):
            if name == '' and not include_default:
                continue
            if name and not self.allow_named_servers:
                continue
            if name in self.spawners:

                yield self.spawners[name]
            else:

                yield orm_spawner

    def _new_orm_spawner(self, server_name):
        ''
        orm_spawner = orm.Spawner(name=server_name)
        self.db.add(orm_spawner)
        orm_spawner.user = self.orm_user
        self.db.commit()
        assert server_name in self.orm_spawners
        return orm_spawner

    def _new_spawner(self, server_name, spawner_class=None, **kwargs):
        ''
        if spawner_class is None:
            spawner_class = self.spawner_class
        self.log.debug("Creating %s for %s:%s", spawner_class, self.name, server_name)

        orm_spawner = self.orm_spawners.get(server_name)
        if orm_spawner is None:
            orm_spawner = self._new_orm_spawner(server_name)
        if server_name == '' and self.state:

            orm_spawner.state = self.state
            self.state = None



        client_id = f'jupyterhub-user-{quote(self.name)}'
        if server_name:
            client_id = f'{client_id}-{quote(server_name)}'

        trusted_alt_names = []
        trusted_alt_names.extend(self.settings.get('trusted_alt_names', []))
        if self.settings.get('subdomain_host'):
            trusted_alt_names.append('DNS:' + self.domain)

        spawn_kwargs = dict(
            user=self,
            orm_spawner=orm_spawner,
            hub=self.settings.get('hub'),
            authenticator=self.authenticator,
            config=self.settings.get('config'),
            proxy_spec=url_path_join(
                self.proxy_spec, url_escape_path(server_name), '/'
            ),
            _deprecated_db_session=self.db,
            oauth_client_id=client_id,
            cookie_options=self.settings.get('cookie_options', {}),
            cookie_host_prefix_enabled=self.settings.get(
                "cookie_host_prefix_enabled", False
            ),
            trusted_alt_names=trusted_alt_names,
            user_options=orm_spawner.user_options or {},
        )

        if self.settings.get('internal_ssl'):
            ssl_kwargs = dict(
                internal_ssl=self.settings.get('internal_ssl'),
                internal_trust_bundles=self.settings.get('internal_trust_bundles'),
                internal_certs_location=self.settings.get('internal_certs_location'),
            )
            spawn_kwargs.update(ssl_kwargs)


        if self.settings.get("public_url"):
            public_url = self.settings["public_url"]
            hub = self.settings.get('hub')
            if hub is None:

                hub_path = "/hub/"
            else:
                hub_path = hub.base_url
            spawn_kwargs["public_hub_url"] = urlunparse(
                public_url._replace(path=hub_path)
            )
        spawn_kwargs["public_url"] = self.public_url(server_name)


        spawn_kwargs.update(kwargs)
        spawner = spawner_class(**spawn_kwargs)
        spawner.load_state(orm_spawner.state or {})
        return spawner


    @property
    def spawner(self):
        return self.spawners['']

    @spawner.setter
    def spawner(self, spawner):
        self.spawners[''] = spawner


    def __getattr__(self, attr):
        if hasattr(self.orm_user, attr):
            return getattr(self.orm_user, attr)
        else:
            raise AttributeError(attr)

    def __setattr__(self, attr, value):
        if not attr.startswith('_') and self.orm_user and hasattr(self.orm_user, attr):
            setattr(self.orm_user, attr, value)
        else:
            super().__setattr__(attr, value)

    def __repr__(self):
        return repr(self.orm_user)

    @property
    def running(self):
        ''
        if not self.spawners:
            return False
        return self.spawner.ready

    @property
    def active(self):
        ''
        if not self.spawners:
            return False
        return any(s.active for s in self.spawners.values())

    @property
    def spawn_pending(self):
        warnings.warn(
            "User.spawn_pending is deprecated in JupyterHub 0.8. Use Spawner.pending",
            DeprecationWarning,
        )
        return self.spawner.pending == 'spawn'

    @property
    def stop_pending(self):
        warnings.warn(
            "User.stop_pending is deprecated in JupyterHub 0.8. Use Spawner.pending",
            DeprecationWarning,
        )
        return self.spawner.pending == 'stop'

    @property
    def server(self):
        return self.spawner.server

    @property
    def escaped_name(self):
        ''
        return url_escape_path(self.name)

    @property
    def json_escaped_name(self):
        ''
        return json.dumps(self.name)[1:-1]

    @property
    def proxy_spec(self):
        ''
        if self.settings.get('subdomain_host'):
            return url_path_join(self.domain, self.base_url, '/')
        else:
            return url_path_join(self.base_url, '/')

    @property
    def domain(self):
        ''
        hook = self.settings.get("subdomain_hook", subdomain_hook_legacy)
        return hook(self.name, self.settings['domain'], kind='user')

    @property
    def dns_safe_name(self):
        ''






        return _strict_dns_safe(self.name, max_length=40)

    @property
    def host(self):
        ''


        if self.settings.get('subdomain_host'):
            parsed = urlparse(self.settings['subdomain_host'])
            h = f"{parsed.scheme}://{self.domain}"
            if parsed.port:
                h = f"{h}:{parsed.port}"
            return h
        elif self.settings.get("public_url"):

            return urlunparse(self.settings["public_url"]._replace(path=""))
        else:
            return ""

    @property
    def url(self):
        ''



        if self.settings.get("subdomain_host"):
            return f"{self.host}{self.base_url}"
        else:
            return self.base_url

    def server_url(self, server_name=''):
        ''
        if not server_name:
            return self.url
        else:
            return url_path_join(self.url, url_escape_path(server_name), "/")

    def public_url(self, server_name=''):
        ''




        url = self.server_url(server_name)
        if "://" not in url:

            if self.settings.get("public_url"):

                url = urlunparse(self.settings["public_url"]._replace(path=url))
            else:


                url = ""
        return url

    def progress_url(self, server_name=''):
        ''
        url_parts = [self.settings['hub'].base_url, 'api/users', self.escaped_name]
        if server_name:
            url_parts.extend(['servers', url_escape_path(server_name), 'progress'])
        else:
            url_parts.extend(['server/progress'])
        return url_path_join(*url_parts)

    async def refresh_auth(self, handler):
        ''


















        authenticator = self.authenticator
        if authenticator is None or not authenticator.refresh_pre_spawn:

            return


        auth_user = await handler.refresh_auth(self, force=True)

        if auth_user:

            return


        self.log.error(
            "Auth expired for %s; cannot spawn until they login again", self.name
        )


        if handler.request.method == 'GET' and handler.current_user is self:
            self.log.info("Redirecting %s to login to refresh auth", self.name)
            url = self.get_login_url()
            next_url = self.request.uri
            sep = '&' if '?' in url else '?'
            url += sep + urlencode(dict(next=next_url))
            self.redirect(url)
            raise web.Finish()
        else:


            raise web.HTTPError(400, f"{self.name}'s authentication has expired")

    async def spawn(self, server_name='', options=None, handler=None):
        ''











        db = self.db

        if handler:
            await self.refresh_auth(handler)

        base_url = url_path_join(self.base_url, url_escape_path(server_name), "/")

        orm_server = orm.Server(base_url=base_url)
        db.add(orm_server)
        note = f"Server at {base_url}"
        db.commit()

        spawner = self.get_spawner(server_name, replace_failed=True)
        spawner.server = server = Server(orm_server=orm_server)
        assert spawner.orm_spawner.server is orm_server

        requested_scopes = spawner.server_token_scopes
        if callable(requested_scopes):
            requested_scopes = await maybe_future(requested_scopes(spawner))
        if not requested_scopes:

            requested_scopes = orm.Role.find(db, "server").scopes
        requested_scopes = set(requested_scopes)


        server_filter = f"={self.name}/{server_name}"
        requested_scopes = {
            scope + server_filter if scope.endswith("!server") else scope
            for scope in requested_scopes
        }

        activity_scope = "users:activity!user"
        if not {activity_scope, "users:activity", "inherit"}.intersection(
            requested_scopes
        ):
            self.log.warning(
                f"Adding required scope {activity_scope} to server token, missing from Spawner.server_token_scopes. Please make sure to add it!"
            )
            requested_scopes |= {activity_scope}

        have_scopes = roles.roles_to_scopes(roles.get_roles_for(self.orm_user))
        have_scopes |= {"inherit"}
        jupyterhub_client = (
            db.query(orm.OAuthClient)
            .filter_by(
                identifier="jupyterhub",
            )
            .one()
        )

        resolved_scopes, excluded_scopes = scopes._resolve_requested_scopes(
            requested_scopes, have_scopes, self.orm_user, jupyterhub_client, db
        )
        if excluded_scopes:



            self.log.debug(
                "Not assigning requested scopes for %s: requested=%s, assigned=%s, excluded=%s",
                spawner._log_name,
                requested_scopes,
                resolved_scopes,
                excluded_scopes,
            )

        api_token = self.new_api_token(note=note, scopes=resolved_scopes)



        spawner.handler = handler


        if options is None:

            options = spawner.orm_spawner.user_options or {}
        else:

            spawner.orm_spawner.user_options = options
            db.commit()

        spawner.user_options = options

        spawner.clear_state()


        spawner.api_token = api_token
        spawner.admin_access = self.settings.get('admin_access', False)
        client_id = spawner.oauth_client_id
        oauth_provider = self.settings.get('oauth_provider')
        if oauth_provider:
            allowed_scopes = await spawner._get_oauth_client_allowed_scopes()
            oauth_client = oauth_provider.add_client(
                client_id,
                api_token,
                url_path_join(self.url, url_escape_path(server_name), 'oauth_callback'),
                allowed_scopes=allowed_scopes,
                description=f"Server at {url_path_join(self.base_url, server_name, '/')}",
            )
            spawner.orm_spawner.oauth_client = oauth_client
        db.commit()


        authenticator = self.authenticator
        try:
            spawner._start_pending = True

            if authenticator:


                await maybe_future(authenticator.pre_spawn_start(self, spawner))


            auth_state = await self.get_auth_state()
            await spawner.run_auth_state_hook(auth_state)


            self.last_activity = spawner.orm_spawner.started = (
                spawner.orm_spawner.last_activity
            ) = utcnow(with_tz=False)
            db.commit()


            await spawner.apply_group_overrides()
            await spawner._run_apply_user_options(spawner.user_options)
            await maybe_future(spawner.run_pre_spawn_hook())
            if self.settings.get('internal_ssl'):
                self.log.debug("Creating internal SSL certs for %s", spawner._log_name)
                hub_paths = await maybe_future(spawner.create_certs())
                spawner.cert_paths = await maybe_future(spawner.move_certs(hub_paths))
            self.log.debug("Calling Spawner.start for %s", spawner._log_name)
            f = maybe_future(spawner.start())

            db.commit()



            await asyncio.wait_for(f, timeout=spawner.start_timeout)
            url = f.result()
            if url:

                if not isinstance(url, str):

                    proto = 'https' if self.settings['internal_ssl'] else 'http'
                    ip, port = url

                    if ':' in ip:

                        ip = f'[{ip}]'
                    url = f'{proto}://{ip}:{int(port)}'
                urlinfo = urlparse(url)
                server.proto = urlinfo.scheme
                server.ip = urlinfo.hostname
                port = urlinfo.port
                if not port:
                    if urlinfo.scheme == 'https':
                        port = 443
                    else:
                        port = 80
                server.port = port
                db.commit()
            else:


                self.log.warning(
                    "DEPRECATION: Spawner.start should return a url or (ip, port) tuple in JupyterHub >= 0.9"
                )
            if spawner.api_token and spawner.api_token != api_token:

                orm_token = orm.APIToken.find(self.db, api_token)
                if orm_token is not None:
                    self.db.delete(orm_token)
                    self.db.commit()

                found = orm.APIToken.find(self.db, spawner.api_token)
                if found:
                    if found.user is not self.orm_user:
                        self.log.error(
                            "%s's server is using %s's token! Revoking this token.",
                            self.name,
                            (found.user or found.service).name,
                        )
                        self.db.delete(found)
                        self.db.commit()
                        raise ValueError(f"Invalid token for {self.name}!")
                else:


                    self.log.warning(
                        "%s's server specified its own API token that's not in the database",
                        self.name,
                    )


                    self.new_api_token(
                        spawner.api_token,
                        generated=False,
                        note=f"retrieved from spawner {server_name}",
                        scopes=resolved_scopes,
                    )

                if oauth_provider:
                    oauth_provider.add_client(
                        client_id,
                        spawner.api_token,
                        url_path_join(
                            self.url, url_escape_path(server_name), 'oauth_callback'
                        ),
                    )
                    db.commit()

        except Exception as e:
            if isinstance(e, AnyTimeoutError):
                self.log.warning(
                    f"{self.name}'s server failed to start"
                    f" in {spawner.start_timeout} seconds, giving up."
                    f"\n{start_timeout_message}"
                )
                e.reason = 'timeout'
                self.settings['statsd'].incr('spawner.failure.timeout')
            elif isinstance(e, web.HTTPError):


                self.log.error(f"Error starting {self.name}'s server: {e}")
                self.settings['statsd'].incr('spawner.failure.error')
                e.reason = 'error'
            else:
                self.log.exception(
                    f"Unhandled error starting {self.name}'s server: {e}"
                )
                self.settings['statsd'].incr('spawner.failure.error')
                e.reason = 'error'
            try:
                await self.stop(spawner.name)
            except Exception:
                self.log.exception(
                    f"Failed to cleanup {self.name}'s server that failed to start",
                    exc_info=True,
                )

            spawner._start_pending = False
            raise e
        finally:

            spawner.handler = None
        spawner.start_polling()


        if self.state is None:
            self.state = {}
        spawner.orm_spawner.state = spawner.get_state()
        db.commit()
        spawner._waiting_for_response = True
        await self._wait_up(spawner)

    async def _wait_up(self, spawner):
        ''




        server = spawner.server
        key = self.settings.get('internal_ssl_key')
        cert = self.settings.get('internal_ssl_cert')
        ca = self.settings.get('internal_ssl_ca')
        ssl_context = make_ssl_context(key, cert, cafile=ca)
        try:
            resp = await server.wait_up(
                http=True,
                timeout=spawner.http_timeout,
                ssl_context=ssl_context,
                extra_path="api",
            )
        except Exception as e:
            if isinstance(e, AnyTimeoutError):
                self.log.warning(
                    f"{self.name}'s server never showed up at {server.url}"
                    f" after {spawner.http_timeout} seconds. Giving up."
                    f"\n{http_timeout_message}"
                )
                e.reason = 'timeout'
                self.settings['statsd'].incr('spawner.failure.http_timeout')
            else:
                e.reason = 'error'
                self.log.exception(
                    f"Unhandled error waiting for {self.name}'s server to show up at {server.url}: {e}"
                )
                self.settings['statsd'].incr('spawner.failure.http_error')
            try:
                await self.stop(spawner.name)
            except Exception:
                self.log.exception(
                    f"Failed to cleanup {self.name}'s server that failed to start",
                    exc_info=True,
                )

            raise e
        else:
            server_version = resp.headers.get('X-JupyterHub-Version')
            _check_version(__version__, server_version, self.log)


            spawner._jupyterhub_version = server_version
        finally:
            spawner._waiting_for_response = False
            spawner._start_pending = False
        return spawner

    async def stop(self, server_name=''):
        ''



        spawner = self.spawners[server_name]
        spawner._spawn_pending = False
        spawner._start_pending = False
        spawner._check_pending = False
        spawner.stop_polling()
        spawner._stop_pending = True

        self.log.debug("Stopping %s", spawner._log_name)

        try:
            api_token = spawner.api_token
            status = await spawner.poll()
            if status is None:
                await spawner.stop()
            self.last_activity = spawner.orm_spawner.last_activity = utcnow(
                with_tz=False
            )

            spawner.server = None
            if not spawner.will_resume:


                orm_token = orm.APIToken.find(self.db, api_token)
                if orm_token:
                    self.db.delete(orm_token)

                for oauth_client in self.db.query(orm.OAuthClient).filter_by(
                    identifier=spawner.oauth_client_id,
                ):
                    self.log.debug("Deleting oauth client %s", oauth_client.identifier)
                    self.db.delete(oauth_client)
            self.db.commit()
            self.log.debug("Finished stopping %s", spawner._log_name)
            RUNNING_SERVERS.dec()
        finally:
            spawner.server = None
            spawner.orm_spawner.started = None
            self.db.commit()

            try:
                await maybe_future(spawner.run_post_stop_hook())
            except Exception:
                self.log.exception("Error in Spawner.post_stop_hook for %s", self)
            spawner.clear_state()
            spawner.orm_spawner.state = spawner.get_state()
            self.db.commit()


            auth = spawner.authenticator
            try:
                if auth:
                    await maybe_future(auth.post_spawn_stop(self, spawner))
            except Exception:
                self.log.exception(
                    "Error in Authenticator.post_spawn_stop for %s", self
                )
            spawner._stop_pending = False
            if not (
                spawner._spawn_future
                and (
                    not spawner._spawn_future.done()
                    or spawner._spawn_future.exception()
                )
            ):


                self.spawners.pop(server_name)
