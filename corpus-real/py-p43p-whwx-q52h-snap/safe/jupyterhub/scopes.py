''
















import functools
import inspect
import re
import warnings
from enum import Enum
from functools import lru_cache
from itertools import chain
from textwrap import indent

import sqlalchemy as sa
from tornado import web
from tornado.log import app_log

from . import orm, roles
from ._memoize import DoNotCache, FrozenDict, lru_cache_key

''




scope_definitions = {
    '(no_scope)': {'description': 'Identify the owner of the requesting entity.'},
    'self': {
        'description': 'Your own resources',
        'doc_description': 'The user’s own resources _(metascope for users, resolves to (no_scope) for services)_',
    },
    'inherit': {
        'description': 'Anything you have access to',
        'doc_description': 'Everything that the token-owning entity can access _(metascope for tokens)_',
    },
    'admin-ui': {
        'description': 'Access the admin page.',
        'doc_description': 'Access the admin page. Permission to take actions via the admin page granted separately.',
    },
    'admin:users': {
        'description': 'Read, modify, create, and delete users and their authentication state, not including their servers or tokens. This is an extremely privileged scope and should be considered tantamount to superuser.',
        'subscopes': ['admin:auth_state', 'users', 'read:roles:users', 'delete:users'],
    },
    'admin:auth_state': {'description': 'Read a user’s authentication state.'},
    'users': {
        'description': 'Read and write permissions to user models (excluding servers, tokens and authentication state).',
        'subscopes': ['read:users', 'list:users', 'users:activity'],
    },
    'delete:users': {
        'description': "Delete users.",
    },
    'list:users': {
        'description': 'List users, including at least their names.',
        'subscopes': ['read:users:name'],
    },
    'read:users': {
        'description': 'Read user models (including the URL of the default server if it is running).',
        'subscopes': [
            'read:users:name',
            'read:users:groups',
            'read:users:activity',
        ],
    },
    'read:users:name': {'description': 'Read names of users.'},
    'read:users:groups': {'description': 'Read users’ group membership.'},
    'read:users:activity': {'description': 'Read time of last user activity.'},
    'read:roles': {
        'description': 'Read role assignments.',
        'subscopes': ['read:roles:users', 'read:roles:services', 'read:roles:groups'],
    },
    'read:roles:users': {'description': 'Read user role assignments.'},
    'read:roles:services': {'description': 'Read service role assignments.'},
    'read:roles:groups': {'description': 'Read group role assignments.'},
    'users:activity': {
        'description': 'Update time of last user activity.',
        'subscopes': ['read:users:activity'],
    },
    'admin:servers': {
        'description': 'Read, start, stop, create and delete user servers and their state.',
        'subscopes': ['admin:server_state', 'servers'],
    },
    'admin:server_state': {'description': 'Read and write users’ server state.'},
    'servers': {
        'description': 'Start and stop user servers.',
        'subscopes': ['read:servers', 'delete:servers'],
    },
    'read:servers': {
        'description': 'Read users’ names and their server models (excluding the server state).',
        'subscopes': ['read:users:name'],
    },
    'delete:servers': {'description': "Stop and delete users' servers."},
    'tokens': {
        'description': 'Read, write, create and delete user tokens.',
        'subscopes': ['read:tokens'],
    },
    'read:tokens': {'description': 'Read user tokens.'},
    'admin:groups': {
        'description': 'Read and write group information, create and delete groups.',
        'subscopes': ['groups', 'read:roles:groups', 'delete:groups'],
    },
    'groups': {
        'description': 'Read and write group information, including adding/removing any users to/from groups. Note: adding users to groups may affect permissions.',
        'subscopes': ['read:groups', 'list:groups'],
    },
    'list:groups': {
        'description': 'List groups, including at least their names.',
        'subscopes': ['read:groups:name'],
    },
    'read:groups': {
        'description': 'Read group models.',
        'subscopes': ['read:groups:name'],
    },
    'read:groups:name': {'description': 'Read group names.'},
    'delete:groups': {
        'description': "Delete groups.",
    },
    'admin:services': {
        'description': 'Create, read, update, delete services, not including services defined from config files.',
        'subscopes': ['list:services', 'read:services', 'read:roles:services'],
    },
    'list:services': {
        'description': 'List services, including at least their names.',
        'subscopes': ['read:services:name'],
    },
    'read:services': {
        'description': 'Read service models.',
        'subscopes': ['read:services:name'],
    },
    'read:services:name': {'description': 'Read service names.'},
    'read:hub': {'description': 'Read detailed information about the Hub.'},
    'access:servers': {
        'description': 'Access user servers via API or browser.',
    },
    'access:services': {
        'description': 'Access services via API or browser.',
    },
    'users:shares': {
        'description': "Read and revoke a user's access to shared servers.",
        'subscopes': [
            'read:users:shares',
        ],
    },
    'read:users:shares': {
        'description': "Read servers shared with a user.",
    },
    'groups:shares': {
        'description': "Read and revoke a group's access to shared servers.",
        'subscopes': [
            'read:groups:shares',
        ],
    },
    'read:groups:shares': {
        'description': "Read servers shared with a group.",
    },
    'read:shares': {
        'description': "Read information about shared access to servers.",
    },
    'shares': {
        'description': "Manage access to shared servers.",
        'subscopes': [
            'access:servers',
            'read:shares',
            'users:shares',
            'groups:shares',
        ],
    },
    'proxy': {
        'description': 'Read information about the proxy’s routing table, sync the Hub with the proxy and notify the Hub about a new proxy.'
    },
    'shutdown': {'description': 'Shutdown the hub.'},
    'read:metrics': {
        'description': "Read prometheus metrics.",
    },
}


class Scope(Enum):
    ALL = True


def _intersection_cache_key(scopes_a, scopes_b, db=None):
    ''
    return (frozenset(scopes_a), frozenset(scopes_b))


@lru_cache_key(_intersection_cache_key)
def _intersect_expanded_scopes(scopes_a, scopes_b, db=None):
    ''












    scopes_a = frozenset(scopes_a)
    scopes_b = frozenset(scopes_b)


    @lru_cache
    def groups_for_user(username):
        ''

        nonlocal needs_db
        needs_db = True
        group_query = (
            db.query(orm.Group.name)
            .join(orm.User.groups)
            .filter(orm.User.name == username)
        )
        return {row[0] for row in group_query}

    @lru_cache
    def groups_for_server(server):
        ''
        username, _, servername = server.partition("/")
        return groups_for_user(username)

    parsed_scopes_a = parse_scopes(scopes_a)
    parsed_scopes_b = parse_scopes(scopes_b)




    needs_db = False

    common_bases = parsed_scopes_a.keys() & parsed_scopes_b.keys()

    common_filters = {}
    warned = False
    for base in common_bases:
        filters_a = parsed_scopes_a[base]
        filters_b = parsed_scopes_b[base]
        if filters_a == Scope.ALL:
            common_filters[base] = filters_b
        elif filters_b == Scope.ALL:
            common_filters[base] = filters_a
        else:
            common_entities = filters_a.keys() & filters_b.keys()
            all_entities = filters_a.keys() | filters_b.keys()



            if (
                db is None
                and not warned
                and 'group' in all_entities
                and ('user' in all_entities or 'server' in all_entities)
            ):


                for a, b in [(filters_a, filters_b), (filters_b, filters_a)]:
                    for b_key in ('user', 'server'):
                        if (
                            not warned
                            and "group" in a
                            and b_key in b
                            and a["group"].difference(b.get("group", []))
                            and b[b_key].difference(a.get(b_key, []))
                        ):
                            warnings.warn(
                                f"{base}[!{b_key}={b[b_key]}, !group={a['group']}] combinations of filters present,"
                                " without db access. Intersection between not considered."
                                " May result in lower than intended permissions.",
                                UserWarning,
                            )
                            warned = True
                            needs_db = True

            common_filters[base] = {
                entity: filters_a[entity] & filters_b[entity]
                for entity in common_entities
            }


            common_servers = initial_common_servers = common_filters[base].get(
                "server", frozenset()
            )
            common_users = initial_common_users = common_filters[base].get(
                "user", frozenset()
            )

            for a, b in [(filters_a, filters_b), (filters_b, filters_a)]:
                if 'server' in a and b.get('server') != a['server']:

                    servers = a['server'].difference(common_servers)


                    if servers and 'user' in b:
                        for server in servers:
                            username, _, servername = server.partition("/")
                            if username in b['user']:
                                common_servers = common_servers | {server}


                    servers = servers.difference(common_servers)
                    if db is not None and servers and 'group' in b:
                        needs_db = True
                        for server in servers:
                            server_groups = groups_for_server(server)
                            if server_groups & b['group']:
                                common_servers = common_servers | {server}


                if (
                    db is not None
                    and 'user' in a
                    and 'group' in b
                    and b.get('user') != a['user']
                ):

                    users = a['user'].difference(common_users)
                    for username in users:
                        groups = groups_for_user(username)
                        if groups & b["group"]:
                            common_users = common_users | {username}



            if common_servers and common_servers != initial_common_servers:
                common_filters[base]["server"] = common_servers



            if common_users and common_users != initial_common_users:
                common_filters[base]["user"] = common_users

    intersection = unparse_scopes(common_filters)
    if needs_db:

        return DoNotCache(intersection)

    return intersection


def get_scopes_for(orm_object):
    ''









    expanded_scopes = set()
    if orm_object is None:
        return expanded_scopes

    if not isinstance(orm_object, orm.Base):
        from .user import User

        if isinstance(orm_object, User):
            orm_object = orm_object.orm_user
        else:
            raise TypeError(
                f"Only allow orm objects or User wrappers, got {orm_object}"
            )

    owner = None
    if isinstance(orm_object, orm.APIToken):
        owner = orm_object.user or orm_object.service
        owner_roles = roles.get_roles_for(owner)
        owner_scopes = roles.roles_to_expanded_scopes(owner_roles, owner)
        if owner is orm_object.user:
            for share in owner.shared_with_me:
                owner_scopes |= frozenset(share.scopes)

        token_scopes = set(orm_object.scopes)
        if 'inherit' in token_scopes:



            return owner_scopes

        token_scopes = set(
            expand_scopes(
                token_scopes,
                owner=owner,
                oauth_client=orm_object.oauth_client,
            )
        )

        if orm_object.client_id != "jupyterhub":


            token_scopes.update(access_scopes(orm_object.oauth_client))



        token_scopes.update(identify_scopes(owner))
        token_scopes = reduce_scopes(token_scopes)

        intersection = _intersect_expanded_scopes(
            token_scopes,
            owner_scopes,
            db=sa.inspect(orm_object).session,
        )
        discarded_token_scopes = token_scopes - intersection


        if discarded_token_scopes:
            app_log.warning(
                f"discarding scopes [{discarded_token_scopes}],"
                f" not present in roles of owner {owner}"
            )
            app_log.debug(
                "Owner %s has scopes: %s\nToken has scopes: %s",
                owner,
                owner_scopes,
                token_scopes,
            )
        expanded_scopes = intersection

        expanded_scopes
    else:
        expanded_scopes = roles.roles_to_expanded_scopes(
            roles.get_roles_for(orm_object),
            owner=orm_object,
        )


        if hasattr(orm_object, "shared_with_me"):
            for share in orm_object.shared_with_me:
                expanded_scopes |= expand_share_scopes(share)
        if isinstance(orm_object, orm.User):
            for group in orm_object.groups:
                for share in group.shared_with_me:
                    expanded_scopes |= expand_share_scopes(share)

    return expanded_scopes


def expand_share_scopes(share):
    ''
    return expand_scopes(
        share.scopes,
        owner=share.user or share.group,
        oauth_client=share.spawner.oauth_client,
    )


@lru_cache
def _expand_self_scope(username):
    ''

















    scope_list = [
        'read:users',
        'read:users:name',
        'read:users:groups',
        'users:shares',
        'read:users:shares',
        'read:shares',
        'users:activity',
        'read:users:activity',
        'servers',
        'delete:servers',
        'read:servers',
        'tokens',
        'read:tokens',
        'access:servers',
    ]

    return frozenset(f"{scope}!user={username}" for scope in scope_list)


@lru_cache(maxsize=65535)
def _expand_scope(scope):
    ''









    scope_name, sep, filter_ = scope.partition('!')


    expanded_scope_names = set()

    def _add_subscopes(scope_name):
        expanded_scope_names.add(scope_name)
        if scope_definitions[scope_name].get('subscopes'):
            for subscope in scope_definitions[scope_name].get('subscopes'):
                _add_subscopes(subscope)

    _add_subscopes(scope_name)


    if filter_:
        expanded_scopes = {
            f"{scope_name}!{filter_}"
            for scope_name in expanded_scope_names



            if not (filter_.startswith("server") and scope_name.startswith("read:user"))
        }
    else:
        expanded_scopes = expanded_scope_names


    return frozenset(expanded_scopes)


def _expand_scopes_key(scopes, owner=None, oauth_client=None):
    ''








    frozen_scopes = frozenset(scopes)
    if owner is None:
        owner_key = None
    else:

        owner_key = (type(owner).__name__, owner.name)
    if oauth_client is None:
        oauth_client_key = None
    else:
        oauth_client_key = oauth_client.identifier
    return (frozen_scopes, owner_key, oauth_client_key)


@lru_cache_key(_expand_scopes_key)
def expand_scopes(scopes, owner=None, oauth_client=None):
    ''












    expanded_scopes = set(chain.from_iterable(map(_expand_scope, scopes)))

    filter_replacements = {
        "user": None,
        "service": None,
        "server": None,
    }
    user_name = None
    if isinstance(owner, orm.User):
        user_name = owner.name
        filter_replacements["user"] = f"user={user_name}"
    elif isinstance(owner, orm.Service):
        filter_replacements["service"] = f"service={owner.name}"

    if oauth_client is not None:
        if oauth_client.service is not None:
            filter_replacements["service"] = f"service={oauth_client.service.name}"
        elif oauth_client.spawner is not None:
            spawner = oauth_client.spawner
            filter_replacements["server"] = f"server={spawner.user.name}/{spawner.name}"

    for scope in expanded_scopes.copy():
        base_scope, _, filter = scope.partition('!')
        if filter in filter_replacements:



            expanded_scopes.remove(scope)
            expanded_filter = filter_replacements[filter]
            if expanded_filter:

                expanded_scopes.add(f'{base_scope}!{expanded_filter}')
            else:
                warnings.warn(
                    f"Not expanding !{filter} filter without target {filter} in {scope}",
                    stacklevel=3,
                )

    if 'self' in expanded_scopes:
        expanded_scopes.remove('self')
        if user_name:
            expanded_scopes |= _expand_self_scope(user_name)
        else:
            warnings.warn(
                f"Not expanding 'self' scope for owner {owner} which is not a User",
                stacklevel=3,
            )



    return frozenset(reduce_scopes(expanded_scopes))


def _resolve_requested_scopes(requested_scopes, have_scopes, user, client, db):
    ''























    allowed_scopes = requested_scopes.intersection(have_scopes)
    disallowed_scopes = requested_scopes.difference(have_scopes)

    if not disallowed_scopes:

        return (allowed_scopes, disallowed_scopes)



    expanded_allowed = expand_scopes(allowed_scopes, user, client)
    expanded_have = expand_scopes(have_scopes, user, client)


    for scope in list(disallowed_scopes):
        expanded_disallowed = expand_scopes({scope}, user, client)

        expanded_disallowed -= expanded_allowed
        if expanded_disallowed:
            allowed_intersection = _intersect_expanded_scopes(
                expanded_disallowed, expanded_have, db=db
            )
        else:
            allowed_intersection = set()

        if allowed_intersection == expanded_disallowed:

            allowed_scopes.add(scope)
            disallowed_scopes.remove(scope)
            expanded_allowed = expand_scopes(allowed_scopes, user, client)

        elif allowed_intersection:


            allowed_scopes |= allowed_intersection
            expanded_allowed = expand_scopes(allowed_scopes, user, client)




        else:

            pass
    return (allowed_scopes, disallowed_scopes)


def _needs_group_expansion(filter_, filter_value, sub_scope):
    ''




    if not (filter_ in {'user', 'server'} and 'group' in sub_scope):
        return False
    if filter_ in sub_scope:
        return filter_value not in sub_scope[filter_]
    else:
        return True


def _has_scope_key(scope, have_scopes, *, post_filter=False, db=None):
    ''
    if isinstance(have_scopes, dict):
        have_scopes = FrozenDict(have_scopes)
    else:
        have_scopes = frozenset(have_scopes)
    return (scope, have_scopes, post_filter)


@lru_cache_key(_has_scope_key)
def has_scope(scope, have_scopes, *, post_filter=False, db=None):
    ''

















    req_scope, _, full_filter = scope.partition("!")
    filter_, _, filter_value = full_filter.partition("=")
    if filter_ and not filter_value:
        raise ValueError(
            f"Unexpanded scope filter {scope} not allowed. Use expanded scopes."
        )

    if isinstance(have_scopes, dict):
        parsed_scopes = have_scopes
    else:
        parsed_scopes = parse_scopes(have_scopes)

    if req_scope not in parsed_scopes:
        return False
    have_scope_filters = parsed_scopes[req_scope]
    if have_scope_filters == Scope.ALL:

        return True

    if not filter_:
        if post_filter:

            return True
        else:
            return False

    if post_filter:
        raise ValueError("post_filter=True only allowed for unfiltered scopes")
    _db_used = False

    if filter_ in have_scope_filters and filter_value in have_scope_filters[filter_]:
        return True


    if filter_ == "server" and "user" in have_scope_filters:
        user_name = filter_value.partition("/")[0]
        if user_name in have_scope_filters["user"]:
            return True

    if db and _needs_group_expansion(filter_, filter_value, have_scope_filters):
        _db_used = True
        if filter_ == "user":
            user_name = filter_value
        elif filter_ == "server":
            user_name = filter_value.partition("/")[0]
        else:
            raise ValueError(
                f"filter_ should be 'user' or 'server' here, not {filter_!r}"
            )
        group_names = have_scope_filters['group']
        have_group_query = (
            db.query(orm.Group.name)
            .join(orm.User.groups)
            .filter(orm.User.name == user_name)
            .filter(orm.Group.name.in_(group_names))
        )
        if have_group_query.count() > 0:
            return DoNotCache(True)

    if _db_used:
        return DoNotCache(False)
    else:
        return False


class ScopeNotFound(KeyError):
    pass


def _check_scopes_exist(scopes, who_for=None):
    ''







    allowed_scopes = set(scope_definitions.keys())
    filter_prefixes = ('!user=', '!service=', '!group=', '!server=')
    exact_filters = {"!user", "!service", "!server"}

    if who_for:
        log_for = f"for {who_for}"
    else:
        log_for = ""

    for scope in scopes:
        scopename, _, filter_ = scope.partition('!')
        if scopename not in allowed_scopes:
            if scopename == "all":
                raise ScopeNotFound("Draft scope 'all' is now called 'inherit'")
            raise ScopeNotFound(f"Scope '{scope}' {log_for} does not exist")
        if filter_:
            full_filter = f"!{filter_}"
            if full_filter not in exact_filters and not full_filter.startswith(
                filter_prefixes
            ):
                raise ScopeNotFound(
                    f"Scope filter {filter_} '{full_filter}' in scope '{scope}' {log_for} does not exist"
                )


def _check_token_scopes(scopes, owner, oauth_client):
    ''









    scopes = set(scopes)
    if scopes.issubset({"inherit"}):

        return
    scopes.discard("inherit")

    token_scopes = expand_scopes(scopes, owner=owner, oauth_client=oauth_client)

    if not token_scopes:
        return

    owner_scopes = get_scopes_for(owner)
    intersection = _intersect_expanded_scopes(
        token_scopes,
        owner_scopes,
        db=sa.inspect(owner).session,
    )
    excess_scopes = token_scopes - intersection

    if excess_scopes:
        raise ValueError(
            f"Not assigning requested scopes {','.join(excess_scopes)} not held by {owner.__class__.__name__} {owner.name}"
        )


@lru_cache_key(frozenset)
def parse_scopes(scope_list):
    ''



















    parsed_scopes = {}
    for scope in scope_list:
        base_scope, _, filter_ = scope.partition('!')
        if not filter_:
            parsed_scopes[base_scope] = Scope.ALL
        elif base_scope not in parsed_scopes:
            parsed_scopes[base_scope] = {}

        if parsed_scopes[base_scope] != Scope.ALL:
            key, _, value = filter_.partition('=')
            if not value:
                raise ValueError(f"Empty string is not a valid filter: {scope}")
            if key not in parsed_scopes[base_scope]:
                parsed_scopes[base_scope][key] = {value}
            else:
                parsed_scopes[base_scope][key].add(value)

    return FrozenDict(parsed_scopes)


@lru_cache_key(FrozenDict)
def unparse_scopes(parsed_scopes):
    ''
    expanded_scopes = set()
    for base, filters in parsed_scopes.items():
        if filters == Scope.ALL:
            expanded_scopes.add(base)
        else:
            for entity, names_list in filters.items():
                for name in names_list:
                    expanded_scopes.add(f'{base}!{entity}={name}')

    return frozenset(expanded_scopes)


@lru_cache_key(frozenset)
def reduce_scopes(expanded_scopes):
    ''




    return unparse_scopes(parse_scopes(expanded_scopes))


def needs_scope(*scopes):
    ''

    for scope in scopes:
        if scope not in scope_definitions:
            raise ValueError(f"Scope {scope} is not a valid scope")

    def scope_decorator(func):
        @functools.wraps(func)
        def _auth_func(self, *args, **kwargs):
            if not self.current_user:



                raise web.HTTPError(
                    403,
                    "Missing or invalid credentials.",
                )

            sig = inspect.signature(func)
            bound_sig = sig.bind(self, *args, **kwargs)
            bound_sig.apply_defaults()

            if not hasattr(self, 'expanded_scopes'):
                self.expanded_scopes = {}
                self.parsed_scopes = {}

            try:
                end_point = self.request.path
            except AttributeError:
                end_point = self.__name__

            s_kwargs = {}
            for resource in {'user', 'server', 'group', 'service'}:
                resource_name = resource + '_name'
                if resource_name in bound_sig.arguments:
                    resource_value = bound_sig.arguments[resource_name]
                    s_kwargs[resource] = resource_value

            if "server" in s_kwargs:

                if "user" not in s_kwargs:
                    raise ValueError(
                        "Cannot filter on 'server_name' without 'user_name'"
                    )
                s_kwargs["server"] = f"{s_kwargs['user']}/{s_kwargs['server']}"
                s_kwargs.pop("user")
            if len(s_kwargs) > 1:
                raise ValueError(
                    f"Cannot filter on more than one field, got {s_kwargs}"
                )
            elif s_kwargs:
                filter_, filter_value = next(iter(s_kwargs.items()))
            else:
                filter_ = filter_value = None

            for scope in scopes:
                if filter_ is not None:
                    scope = f"{scope}!{filter_}={filter_value}"
                app_log.debug("Checking access to %s via scope %s", end_point, scope)
                has_access = has_scope(
                    scope,
                    self.parsed_scopes,
                    post_filter=filter_ is None,
                    db=self.db,
                )
                if has_access:
                    return func(self, *args, **kwargs)
            app_log.warning(
                "Not authorizing access to %s. Requires any of [%s] on %s, not derived from scopes [%s]",
                end_point,
                ", ".join(scopes),
                "*" if filter_ is None else f"{filter_}={filter_value}",
                ", ".join(self.expanded_scopes),
            )
            if filter_ and any(scope in self.parsed_scopes for scope in scopes):


                raise web.HTTPError(
                    404, "No access to resources or resources not found"
                )
            raise web.HTTPError(
                403,
                "Action is not authorized with current scopes;"
                f" requires any of [{', '.join(scopes)}]",
            )

        return _auth_func

    return scope_decorator


def _identify_key(obj=None):
    if obj is None:
        return None
    else:
        return (type(obj).__name__, obj.name)


@lru_cache_key(_identify_key)
def identify_scopes(obj=None):
    ''









    if obj is None:
        return frozenset(f"read:users:{field}!user" for field in {"name", "groups"})
    elif isinstance(obj, orm.User):
        return frozenset(
            f"read:users:{field}!user={obj.name}" for field in {"name", "groups"}
        )
    elif isinstance(obj, orm.Service):
        return frozenset(
            f"read:services:{field}!service={obj.name}" for field in {"name"}
        )
    else:
        raise TypeError(f"Expected orm.User or orm.Service, got {obj!r}")


def _access_cache_key(oauth_client=None, *, spawner=None, service=None):
    if oauth_client:
        return ("oauth", oauth_client.identifier)
    elif spawner:
        return ("spawner", spawner.user.name, spawner.name)
    elif service:
        return ("service", service.name)


@lru_cache_key(_access_cache_key)
def access_scopes(oauth_client=None, *, spawner=None, service=None):
    ''
    scopes = set()
    if oauth_client and oauth_client.identifier == "jupyterhub":
        return frozenset()
    if spawner is None and oauth_client:
        spawner = oauth_client.spawner
    if spawner:
        scopes.add(f"access:servers!server={spawner.user.name}/{spawner.name}")
    else:
        if service is None:
            service = oauth_client.service
        if service:
            scopes.add(f"access:services!service={service.name}")
        else:
            app_log.warning(
                f"OAuth client {oauth_client} has no associated service or spawner!"
            )
    return frozenset(scopes)


def _check_scope_key(sub_scope, orm_resource, kind):
    ''
    if kind == 'server':
        resource_key = (orm_resource.user.name, orm_resource.name)
    else:
        resource_key = orm_resource.name
    return (sub_scope, resource_key, kind)


@lru_cache_key(_check_scope_key)
def check_scope_filter(sub_scope, orm_resource, kind):
    ''







    if sub_scope is Scope.ALL:
        return True
    elif kind in sub_scope and orm_resource.name in sub_scope[kind]:
        return True

    if kind == 'server':
        server_format = f"{orm_resource.user.name}/{orm_resource.name}"
        if server_format in sub_scope.get(kind, []):
            return True

        if 'user' in sub_scope and orm_resource.user.name in sub_scope['user']:
            return True

        orm_resource = orm_resource.user
        kind = 'user'

    if kind == 'user' and 'group' in sub_scope:
        group_names = {group.name for group in orm_resource.groups}
        user_in_group = bool(group_names & set(sub_scope['group']))

        return DoNotCache(user_in_group)
    return False


def describe_parsed_scopes(parsed_scopes, username=None):
    ''



    descriptions = []
    for scope, filters in parsed_scopes.items():
        if filters == Scope.ALL:

            filter_text = ""
        else:
            filter_chunks = []
            for kind, names in filters.items():
                if kind == 'user' and names == {username}:
                    filter_chunks.append("only you")
                else:
                    if len(names) == 1:
                        filter_chunks.append(f"{kind}: {list(names)[0]}")
                    else:
                        filter_chunks.append(f"{kind}s: {', '.join(names)}")
            filter_text = "; or ".join(filter_chunks)
        descriptions.append(
            {
                "scope": scope,
                "description": scope_definitions[scope]["description"],
                "filter": filter_text,
            }
        )
    return descriptions


@lru_cache_key(lambda raw_scopes, username=None: (frozenset(raw_scopes), username))
def describe_raw_scopes(raw_scopes, username=None):
    ''



    descriptions = []
    for raw_scope in raw_scopes:
        scope, _, filter_ = raw_scope.partition("!")
        if not filter_:

            filter_text = ""
        elif filter_ == "user":
            filter_text = "only you"
        else:
            kind, _, name = filter_.partition("=")
            if kind == "user" and name == username:
                filter_text = "only you"
            else:
                kind_text = kind
                if kind == 'group':
                    kind_text = "users in group"
                filter_text = f"{kind_text} {name}"
        descriptions.append(
            {
                "scope": scope,
                "description": scope_definitions[scope]["description"],
                "filter": filter_text,
            }
        )

    return tuple(descriptions)






_custom_scope_pattern = re.compile(r"^custom:[a-z0-9][a-z0-9_\-\*:]+[a-z0-9_\*]$")



_custom_scope_description = """
Custom scopes must start with `custom:`
and contain only lowercase ascii letters, numbers, hyphen, underscore, colon, and asterisk (-_:*).
The part after `custom:` must start with a letter or number.
Scopes may not end with a hyphen or colon.
"""


def define_custom_scopes(scopes):
    """Define custom scopes

    Adds custom scopes to the scope_definitions dict.

    Scopes must start with `custom:`.
    It is recommended to name custom scopes with a pattern like::

        custom:$your-project:$action:$resource

    e.g.::

        custom:jupyter_server:read:contents

    That makes them easy to parse and avoids collisions across projects.

    `scopes` must have at least one scope definition,
    and each scope definition must have a `description`,
    which will be displayed on the oauth authorization page,
    and _may_ have a `subscopes` list of other scopes if having one scope
    should imply having other, more specific scopes.

    Args:

    scopes: dict
        A dictionary of scope definitions.
        The keys are the scopes,
        while the values are dictionaries with at least a `description` field,
        and optional `subscopes` field.
        CUSTOM_SCOPE_DESCRIPTION
    Examples::

        define_custom_scopes(
            {
                "custom:jupyter_server:read:contents": {
                    "description": "read-only access to files in a Jupyter server",
                },
                "custom:jupyter_server:read": {
                    "description": "read-only access to a Jupyter server",
                    "subscopes": [
                        "custom:jupyter_server:read:contents",
                        "custom:jupyter_server:read:kernels",
                        "...",
                },
            }
        )
    """.replace("CUSTOM_SCOPE_DESCRIPTION", indent(_custom_scope_description, " " * 8))
    for scope, scope_definition in scopes.items():
        if scope in scope_definitions and scope_definitions[scope] != scope_definition:
            raise ValueError(
                f"Cannot redefine scope {scope}={scope_definition}. Already have {scope}={scope_definitions[scope]}"
            )
        if not _custom_scope_pattern.match(scope):

            raise ValueError(
                f"Invalid scope name: {scope!r}.\n{_custom_scope_description}"
                " and contain only lowercase ascii letters, numbers, hyphen, underscore, colon, and asterisk."
                " The part after `custom:` must start with a letter or number."
                " Scopes may not end with a hyphen or colon."
            )
        if "description" not in scope_definition:
            raise ValueError(
                f"scope {scope}={scope_definition} missing key 'description'"
            )
        if "subscopes" in scope_definition:
            subscopes = scope_definition["subscopes"]
            if not isinstance(subscopes, list) or not all(
                isinstance(s, str) for s in subscopes
            ):
                raise ValueError(
                    f"subscopes must be a list of scope strings, got {subscopes!r}"
                )
            for subscope in subscopes:
                if subscope not in scopes:
                    if subscope in scope_definitions:
                        raise ValueError(
                            f"non-custom subscope {subscope} in {scope}={scope_definition} is not allowed."
                            f" Custom scopes may only have custom subscopes."
                            f" Roles should be used to assign multiple scopes together."
                        )
                    raise ValueError(
                        f"subscope {subscope} in {scope}={scope_definition} not found. All scopes must be defined."
                    )

        extra_keys = set(scope_definition.keys()).difference(
            ["description", "subscopes"]
        )
        if extra_keys:
            warnings.warn(
                f"Ignoring unrecognized key(s) {', '.join(extra_keys)!r} in {scope}={scope_definition}",
                UserWarning,
                stacklevel=2,
            )
        app_log.info(f"Defining custom scope {scope}")

        app_log.debug("Defining custom scope %s=%s", scope, scope_definition)
        scope_definitions[scope] = scope_definition
