''



import enum
import json
import numbers
import secrets
from base64 import decodebytes, encodebytes
from datetime import timedelta
from functools import lru_cache, partial
from itertools import chain

import alembic.command
import alembic.config
import sqlalchemy
from alembic.script import ScriptDirectory
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    MetaData,
    Table,
    Unicode,
    create_engine,
    event,
    exc,
    inspect,
    or_,
    select,
    text,
)
from sqlalchemy.orm import (
    Session,
    declarative_base,
    declared_attr,
    interfaces,
    joinedload,
    object_session,
    relationship,
    sessionmaker,
)
from sqlalchemy.pool import StaticPool
from sqlalchemy.types import LargeBinary, Text, TypeDecorator
from tornado.log import app_log

from .utils import compare_token, fmt_ip_url, hash_token, new_token, random_port, utcnow


utcnow = partial(utcnow, with_tz=False)


class JSONDict(TypeDecorator):
    ''







    impl = Text

    def _json_default(self, obj):
        ''




        if not isinstance(obj, bytes):
            app_log.warning(
                "Non-jsonable data in user_options: %r; will persist None.", type(obj)
            )
            return None

        return {"__jupyterhub_bytes__": True, "data": encodebytes(obj).decode('ascii')}

    def _object_hook(self, dct):
        ''
        if dct.get("__jupyterhub_bytes__", False):
            return decodebytes(dct['data'].encode('ascii'))
        return dct

    def process_bind_param(self, value, dialect):
        if value is not None:
            value = json.dumps(value, default=self._json_default)
        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            value = json.loads(value, object_hook=self._object_hook)
        return value


class JSONList(JSONDict):
    ''











    def process_bind_param(self, value, dialect):
        if isinstance(value, (list, tuple)):
            value = json.dumps(value)
        if isinstance(value, set):

            value = json.dumps(sorted(value))

        return value

    def process_result_value(self, value, dialect):
        if value is None:
            return []
        else:
            value = json.loads(value)
        return value


meta = MetaData(
    naming_convention={
        "ix": "ix_%(column_0_label)s",
        "uq": "uq_%(table_name)s_%(column_0_name)s",
        "ck": "ck_%(table_name)s_%(constraint_name)s",
        "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
        "pk": "pk_%(table_name)s",
    }
)

Base = declarative_base(metadata=meta)
Base.log = app_log


class Server(Base):
    ''




    __tablename__ = 'servers'
    id = Column(Integer, primary_key=True)

    proto = Column(Unicode(15), default='http')
    ip = Column(Unicode(255), default='')
    port = Column(Integer, default=random_port)
    base_url = Column(Unicode(255), default='/')
    cookie_name = Column(Unicode(255), default='cookie')

    service = relationship("Service", back_populates="server", uselist=False)
    spawner = relationship("Spawner", back_populates="server", uselist=False)

    def __repr__(self):
        return f"<Server({fmt_ip_url(self.ip)}:{self.port})>"





_role_associations = {}

for entity in (
    'user',
    'group',
    'service',
):
    table = Table(
        f'{entity}_role_map',
        Base.metadata,
        Column(
            f'{entity}_id',
            ForeignKey(f'{entity}s.id', ondelete='CASCADE'),
            primary_key=True,
        ),
        Column(
            'role_id',
            ForeignKey('roles.id', ondelete='CASCADE'),
            primary_key=True,
        ),
        Column('managed_by_auth', Boolean, default=False, nullable=False),
    )

    _role_associations[entity] = type(
        entity.title() + 'RoleMap', (Base,), {'__table__': table}
    )


class Role(Base):
    ''

    __tablename__ = 'roles'
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(Unicode(255), unique=True)
    description = Column(Unicode(1023))
    scopes = Column(JSONList, default=[])

    users = relationship('User', secondary='user_role_map', back_populates='roles')
    services = relationship(
        'Service', secondary='service_role_map', back_populates='roles'
    )
    groups = relationship('Group', secondary='group_role_map', back_populates='roles')

    managed_by_auth = Column(Boolean, default=False, nullable=False)

    def __repr__(self):
        return f"<{self.__class__.__name__} {self.name} ({self.description}) - scopes: {self.scopes}>"

    @classmethod
    def find(cls, db, name):
        ''


        return db.query(cls).filter(cls.name == name).first()



user_group_map = Table(
    'user_group_map',
    Base.metadata,
    Column('user_id', ForeignKey('users.id', ondelete='CASCADE'), primary_key=True),
    Column('group_id', ForeignKey('groups.id', ondelete='CASCADE'), primary_key=True),
)


class Group(Base):
    ''

    __tablename__ = 'groups'
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(Unicode(255), unique=True)
    users = relationship('User', secondary='user_group_map', back_populates='groups')
    properties = Column(JSONDict, default={})
    roles = relationship(
        'Role', secondary='group_role_map', back_populates='groups', lazy="selectin"
    )

    shared_with_me = relationship(
        "Share",
        back_populates="group",
        cascade="all, delete-orphan",
        lazy="selectin",
    )


    kind = "group"

    def __repr__(self):
        return f"<{self.__class__.__name__} {self.name}>"

    @classmethod
    def find(cls, db, name):
        ''


        return db.query(cls).filter(cls.name == name).first()


class User(Base):
    ''





















    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(Unicode(255), unique=True)

    roles = relationship(
        'Role',
        secondary='user_role_map',
        back_populates='users',
        lazy="selectin",
    )

    _orm_spawners = relationship(
        "Spawner", back_populates="user", cascade="all, delete-orphan"
    )

    @property
    def orm_spawners(self):
        return {s.name: s for s in self._orm_spawners}

    admin = Column(Boolean(create_constraint=False), default=False)
    created = Column(DateTime, default=utcnow)
    last_activity = Column(DateTime, nullable=True)

    api_tokens = relationship(
        "APIToken", back_populates="user", cascade="all, delete-orphan"
    )
    groups = relationship(
        "Group",
        secondary='user_group_map',
        back_populates="users",
        lazy="selectin",
    )
    oauth_codes = relationship(
        "OAuthCode", back_populates="user", cascade="all, delete-orphan"
    )


    shares = relationship(
        "Share",
        back_populates="owner",
        cascade="all, delete-orphan",
        foreign_keys="Share.owner_id",
    )
    share_codes = relationship(
        "ShareCode",
        back_populates="owner",
        cascade="all, delete-orphan",
        foreign_keys="ShareCode.owner_id",
    )
    shared_with_me = relationship(
        "Share",
        back_populates="user",
        cascade="all, delete-orphan",
        foreign_keys="Share.user_id",
        lazy="selectin",
    )

    @property
    def all_shared_with_me(self):
        ''




        return list(
            chain(
                self.shared_with_me,
                *[group.shared_with_me for group in self.groups],
            )
        )

    cookie_id = Column(Unicode(255), default=new_token, nullable=False, unique=True)


    state = Column(JSONDict)


    encrypted_auth_state = Column(LargeBinary)



    kind = "user"

    def __repr__(self):
        return f"<{self.__class__.__name__}({self.name} {sum(bool(s.server) for s in self._orm_spawners)}/{len(self._orm_spawners)} running)>"

    def new_api_token(self, token=None, **kwargs):
        ''



        return APIToken.new(token=token, user=self, **kwargs)

    @classmethod
    def find(cls, db, name):
        ''


        return db.query(cls).filter(cls.name == name).first()


class Spawner(Base):
    ''

    __tablename__ = 'spawners'

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'))
    user = relationship("User", back_populates="_orm_spawners")

    server_id = Column(Integer, ForeignKey('servers.id', ondelete='SET NULL'))
    server = relationship(
        Server,
        back_populates="spawner",
        lazy="joined",
        single_parent=True,
        cascade="all, delete-orphan",
    )

    shares = relationship(
        "Share", back_populates="spawner", cascade="all, delete-orphan"
    )
    share_codes = relationship(
        "ShareCode", back_populates="spawner", cascade="all, delete-orphan"
    )

    state = Column(JSONDict)
    name = Column(Unicode(255))

    started = Column(DateTime)
    last_activity = Column(DateTime, nullable=True)
    user_options = Column(JSONDict)


    oauth_client_id = Column(
        Unicode(255),
        ForeignKey(
            'oauth_clients.identifier',
            ondelete='SET NULL',
        ),
    )
    oauth_client = relationship(
        'OAuthClient',
        back_populates="spawner",
        cascade="all, delete-orphan",
        single_parent=True,
    )





    active = running = ready = False
    pending = None

    @property
    def orm_spawner(self):
        return self


class Service(Base):
    ''
















    __tablename__ = 'services'
    id = Column(Integer, primary_key=True, autoincrement=True)


    name = Column(Unicode(255), unique=True)
    admin = Column(Boolean(create_constraint=False), default=False)
    roles = relationship(
        'Role', secondary='service_role_map', back_populates='services', lazy="selectin"
    )

    url = Column(Unicode(2047), nullable=True)

    oauth_client_allowed_scopes = Column(JSONList, nullable=True)

    info = Column(JSONDict, nullable=True)

    display = Column(Boolean, nullable=True)

    oauth_no_confirm = Column(Boolean, nullable=True)

    command = Column(JSONList, nullable=True)

    cwd = Column(Unicode(4095), nullable=True)

    environment = Column(JSONDict, nullable=True)

    user = Column(Unicode(255), nullable=True)

    from_config = Column(Boolean, default=True)

    api_tokens = relationship(
        "APIToken", back_populates="service", cascade="all, delete-orphan"
    )


    _server_id = Column(Integer, ForeignKey('servers.id', ondelete='SET NULL'))
    server = relationship(
        Server,
        back_populates="service",
        single_parent=True,
        cascade="all, delete-orphan",
    )
    pid = Column(Integer)


    oauth_client_id = Column(
        Unicode(255),
        ForeignKey(
            'oauth_clients.identifier',
            ondelete='SET NULL',
        ),
    )

    oauth_client = relationship(
        'OAuthClient',
        back_populates="service",
        cascade="all, delete-orphan",
        single_parent=True,
    )


    kind = "service"

    def new_api_token(self, token=None, **kwargs):
        ''


        return APIToken.new(token=token, service=self, **kwargs)

    @classmethod
    def find(cls, db, name):
        ''



        return db.query(cls).filter(cls.name == name).first()


class Expiring:
    ''





    now = staticmethod(utcnow)
    expires_at = None

    @property
    def expires_in(self):
        ''



        if self.expires_at:
            delta = self.expires_at - self.now()
            if isinstance(delta, timedelta):
                delta = delta.total_seconds()
            return delta
        else:
            return None

    @property
    def expired(self):
        ''
        if not self.expires_at:
            return False
        else:
            return self.expires_in <= 0

    @classmethod
    def purge_expired(cls, db):
        ''
        now = cls.now()
        deleted = False
        for obj in (
            db.query(cls).filter(cls.expires_at != None).filter(cls.expires_at < now)
        ):
            app_log.debug("Purging expired %s", obj)
            deleted = True
            db.delete(obj)
        if deleted:
            db.commit()


class Hashed(Expiring):
    ''

    prefix_length = 4
    algorithm = "sha512"
    rounds = 16384
    salt_bytes = 8
    min_length = 8



    generated = True
    generated_salt_bytes = 8
    generated_rounds = 1

    @property
    def token(self):
        raise AttributeError(f"{self.__class__.__name__}.token is write-only")

    @token.setter
    def token(self, token):
        ''
        self.prefix = token[: self.prefix_length]
        if self.generated:



            rounds = self.generated_rounds
            salt_bytes = self.generated_salt_bytes
        else:
            rounds = self.rounds
            salt_bytes = self.salt_bytes
        self.hashed = hash_token(
            token, rounds=rounds, salt=salt_bytes, algorithm=self.algorithm
        )

    def match(self, token):
        ''
        return compare_token(self.hashed, token)

    @classmethod
    def check_token(cls, db, token):
        ''
        if len(token) < cls.min_length:
            raise ValueError(
                f"{cls.__name__}.token must be at least {cls.min_length} characters, got {len(token)}: {token[: cls.prefix_length]}..."
            )
        found = cls.find(db, token)
        if found:
            raise ValueError(
                f"Collision on {cls.__name__}: {token[: cls.prefix_length]}..."
            )

    @classmethod
    def find_prefix(cls, db, token):
        ''







        prefix = token[: cls.prefix_length]


        prefix_match = db.query(cls).filter_by(prefix=prefix)
        prefix_match = prefix_match.filter(
            or_(cls.expires_at == None, cls.expires_at >= cls.now())
        )
        return prefix_match

    @classmethod
    def find(cls, db, token):
        ''






        prefix_match = cls.find_prefix(db, token).options(
            joinedload(cls.user), joinedload(cls.service)
        )

        for orm_token in prefix_match:
            if orm_token.match(token):
                return orm_token


class _Share:
    ''

    id = Column(Integer, primary_key=True, autoincrement=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)





    @declared_attr
    def owner_id(self):
        return Column(Integer, ForeignKey('users.id', ondelete="CASCADE"))

    @declared_attr
    def owner(self):


        return relationship(
            "User",
            back_populates=self.__tablename__,
            foreign_keys=[self.owner_id],
            lazy="selectin",
        )


    @declared_attr
    def spawner_id(self):
        return Column(Integer, ForeignKey('spawners.id', ondelete="CASCADE"))

    @declared_attr
    def spawner(self):
        return relationship(
            "Spawner",
            back_populates=self.__tablename__,
            lazy="selectin",
        )


    scopes = Column(JSONList)
    expires_at = Column(DateTime, nullable=True)

    @classmethod
    def apply_filter(cls, scopes, spawner):
        ''



        return cls._apply_filter(frozenset(scopes), spawner.user.name, spawner.name)

    @staticmethod
    @lru_cache
    def _apply_filter(scopes, owner_name, server_name):
        ''




        filtered_scopes = []
        server_filter = f"server={owner_name}/{server_name}"
        for scope in scopes:
            base_scope, _, filter = scope.partition("!")
            if filter and filter != server_filter:
                raise ValueError(
                    f"!{filter} not allowed on sharing {scope}, only !{server_filter}"
                )
            filtered_scopes.append(f"{base_scope}!{server_filter}")
        return frozenset(filtered_scopes)


class Share(_Share, Expiring, Base):
    ''






    __tablename__ = "shares"


    user_id = Column(Integer, ForeignKey('users.id', ondelete="CASCADE"), nullable=True)
    user = relationship(
        "User", back_populates="shared_with_me", foreign_keys=[user_id], lazy="selectin"
    )

    group_id = Column(
        Integer, ForeignKey('groups.id', ondelete="CASCADE"), nullable=True
    )
    group = relationship("Group", back_populates="shared_with_me", lazy="selectin")

    def __repr__(self):
        if self.user:
            kind = "user"
            name = self.user.name
        elif self.group:
            kind = "group"
            name = self.group.name
        else:  # pragma: no cover
            kind = "deleted"
            name = "unknown"

        if self.owner and self.spawner:
            server_name = f"{self.owner.name}/{self.spawner.name}"
        else:  # pragma: n cover
            server_name = "unknown/deleted"

        return f"<{self.__class__.__name__}(server={server_name}, scopes={self.scopes}, {kind}={name})>"

    @staticmethod
    def _share_with_key(share_with):
        ''





        if isinstance(share_with, User):
            return "user_id"
        elif isinstance(share_with, Group):
            return "group_id"
        else:
            raise TypeError(
                f"Can only share with orm.User or orm.Group, not {share_with!r}"
            )

    @classmethod
    def find(cls, db, spawner, share_with):
        ''




        filter_by = {
            cls._share_with_key(share_with): share_with.id,
            "spawner_id": spawner.id,
            "owner_id": spawner.user.id,
        }
        return db.query(Share).filter_by(**filter_by).one_or_none()

    @staticmethod
    def _get_log_name(spawner, share_with):
        ''
        return (
            f"{share_with.kind}:{share_with.name} on {spawner.user.name}/{spawner.name}"
        )

    @property
    def _log_name(self):
        return self._get_log_name(self.spawner, self.user or self.group)

    @classmethod
    def grant(cls, db, spawner, share_with, scopes=None):
        ''




        if scopes is None:
            scopes = frozenset(
                [f"access:servers!server={spawner.user.name}/{spawner.name}"]
            )
        scopes = cls._apply_filter(frozenset(scopes), spawner.user.name, spawner.name)

        if not scopes:
            raise ValueError("Must specify scopes to grant.")


        share = cls.find(db, spawner, share_with)
        share_with_log = cls._get_log_name(spawner, share_with)
        if share is not None:


            existing_scopes = set(share.scopes)
            added_scopes = set(scopes).difference(existing_scopes)
            if not added_scopes:
                app_log.info(f"No new scopes for {share_with_log}")
                return share
            new_scopes = sorted(existing_scopes | added_scopes)
            app_log.info(f"Granting scopes {sorted(added_scopes)} for {share_with_log}")
            share.scopes = new_scopes
            db.commit()
        else:

            app_log.info(f"Sharing scopes {sorted(scopes)} for {share_with_log}")
            share = cls(
                created_at=cls.now(),

                owner=spawner.user,
                spawner=spawner,
                scopes=sorted(scopes),
            )
            if share_with.kind == "user":
                share.user = share_with
            elif share_with.kind == "group":
                share.group = share_with
            else:
                raise TypeError(f"Expected user or group, got {share_with!r}")
            db.add(share)
            db.commit()
        return share

    @classmethod
    def revoke(cls, db, spawner, share_with, scopes=None):
        ''



        share = cls.find(db, spawner, share_with)
        if share is None:
            _log_name = cls._get_log_name(spawner, share_with)
            app_log.info(f"No permissions to revoke from {_log_name}")
            return
        else:
            _log_name = share._log_name

        if scopes is None:
            app_log.info(f"Revoked all permissions from {_log_name}")
            db.delete(share)
            db.commit()
            return None


        new_scopes = [scope for scope in share.scopes if scope not in scopes]
        revoked_scopes = [scope for scope in scopes if scope in set(share.scopes)]
        if new_scopes == share.scopes:
            app_log.info(f"No change in scopes for {_log_name}")
            return share
        elif not new_scopes:

            app_log.info(f"Revoked all permissions from {_log_name}")
            db.delete(share)
            db.commit()
        else:
            app_log.info(f"Revoked {revoked_scopes} from {_log_name}")
            share.scopes = new_scopes
            db.commit()

        if new_scopes:
            return share
        else:
            return None


class ShareCode(_Share, Hashed, Base):
    ''






    __tablename__ = "share_codes"

    hashed = Column(Unicode(255), unique=True)
    prefix = Column(Unicode(16), index=True)
    exchange_count = Column(Integer, default=0)
    last_exchanged_at = Column(DateTime, nullable=True, default=None)

    _code_bytes = 32
    default_expires_in = 86400

    def __repr__(self):
        if self.owner and self.spawner:
            server_name = f"{self.owner.name}/{self.spawner.name}"
        else:
            server_name = "unknown/deleted"

        return f"<{self.__class__.__name__}(id={self.id}, server={server_name}, scopes={self.scopes}, expires_at={self.expires_at})>"

    @classmethod
    def new(
        cls,
        db,
        spawner,
        *,
        scopes,
        expires_in=None,
        **kwargs,
    ):
        ''
        app_log.info(f"Creating share code for {spawner.user.name}/{spawner.name}")

        kwargs["scopes"] = sorted(cls.apply_filter(scopes, spawner))
        if not expires_in:
            expires_in = cls.default_expires_in
        kwargs["expires_at"] = utcnow() + timedelta(seconds=expires_in)
        kwargs["spawner"] = spawner
        kwargs["owner"] = spawner.user
        code = secrets.token_urlsafe(cls._code_bytes)


        share_code = cls(**kwargs)

        share_code.token = code

        db.add(share_code)
        db.commit()
        return (share_code, code)

    @classmethod
    def find(cls, db, code, *, spawner=None):
        ''
        prefix_match = cls.find_prefix(db, code)
        if spawner:
            prefix_match = prefix_match.filter_by(spawner_id=spawner.id)
        for share_code in prefix_match:
            if share_code.match(code):
                return share_code

    def exchange(self, share_with):
        ''



        db = inspect(self).session
        share_code_log = f"Share code {self.prefix}..."
        if self.expired:
            db.delete(self)
            db.commit()
            raise ValueError(f"{share_code_log} expired")

        share_with_log = f"{share_with.kind}:{share_with.name} on {self.owner.name}/{self.spawner.name}"
        app_log.info(f"Exchanging {share_code_log} for {share_with_log}")
        share = Share.grant(db, self.spawner, share_with, self.scopes)


        self.exchange_count += 1
        self.last_exchanged_at = self.now()
        db.commit()
        return share







class GrantType(enum.Enum):

    authorization_code = 'authorization_code'
    implicit = 'implicit'
    password = 'password'
    client_credentials = 'client_credentials'
    refresh_token = 'refresh_token'


class APIToken(Hashed, Base):
    ''

    __tablename__ = 'api_tokens'

    user_id = Column(
        Integer,
        ForeignKey('users.id', ondelete="CASCADE"),
        nullable=True,
    )
    service_id = Column(
        Integer,
        ForeignKey('services.id', ondelete="CASCADE"),
        nullable=True,
    )

    user = relationship("User", back_populates="api_tokens")
    service = relationship("Service", back_populates="api_tokens")
    oauth_client = relationship("OAuthClient", back_populates="access_tokens")

    id = Column(Integer, primary_key=True)
    hashed = Column(Unicode(255), unique=True)
    prefix = Column(Unicode(16), index=True)

    @property
    def api_id(self):
        return f"a{self.id}"

    @property
    def owner(self):
        return self.user or self.service


    client_id = Column(
        Unicode(255),
        ForeignKey(
            'oauth_clients.identifier',
            ondelete='CASCADE',
        ),
    )











    session_id = Column(Unicode(255), nullable=True)


    now = staticmethod(utcnow)
    created = Column(DateTime, default=utcnow)
    expires_at = Column(DateTime, default=None, nullable=True)
    last_activity = Column(DateTime)
    note = Column(Unicode(1023))
    scopes = Column(JSONList, default=[])

    def __repr__(self):
        if self.user is not None:
            kind = 'user'
            name = self.user.name
        elif self.service is not None:
            kind = 'service'
            name = self.service.name
        else:

            kind = 'owner'
            name = 'unknown'
        return f"<{self.__class__.__name__}('{self.prefix}...', {kind}='{name}', client_id={self.client_id!r})>"

    @classmethod
    def find(cls, db, token, *, kind=None):
        ''






        prefix_match = cls.find_prefix(db, token)
        if kind == 'user':
            prefix_match = prefix_match.filter(cls.user_id != None)
        elif kind == 'service':
            prefix_match = prefix_match.filter(cls.service_id != None)
        elif kind is not None:
            raise ValueError(f"kind must be 'user', 'service', or None, not {kind!r}")
        for orm_token in prefix_match:
            if orm_token.match(token):
                if not orm_token.client_id:
                    app_log.warning(
                        "Deleting stale oauth token for %s with no client",
                        orm_token.user and orm_token.user.name,
                    )
                    db.delete(orm_token)
                    db.commit()
                    return
                return orm_token

    @classmethod
    def new(
        cls,
        token=None,
        *,
        user=None,
        service=None,
        roles=None,
        scopes=None,
        note='',
        generated=True,
        session_id=None,
        expires_in=None,
        client_id=None,
        oauth_client=None,
    ):
        ''
        assert user or service
        assert not (user and service)
        db = inspect(user or service).session
        if token is None:
            token = new_token()


            generated = True
        else:
            cls.check_token(db, token)


        from .roles import roles_to_scopes

        if scopes is not None and roles is not None:
            raise ValueError(
                "Can only assign one of scopes or roles when creating tokens."
            )

        elif scopes is None and roles is None:


            default_token_role = Role.find(db, 'token')
            if not default_token_role:
                scopes = ["inherit"]
            else:
                scopes = roles_to_scopes([default_token_role])
        elif roles is not None:







            orm_roles = []
            for rolename in roles:
                role = Role.find(db, name=rolename)
                if role is None:
                    raise ValueError(f"No such role: {rolename}")
                orm_roles.append(role)
            scopes = roles_to_scopes(orm_roles)

        if oauth_client is None:

            if client_id is None:

                client_id = "jupyterhub"
            oauth_client = db.query(OAuthClient).filter_by(identifier=client_id).one()
        if client_id is None:
            client_id = oauth_client.identifier


        from .scopes import _check_scopes_exist, _check_token_scopes

        _check_scopes_exist(scopes, who_for="token")
        _check_token_scopes(scopes, owner=user or service, oauth_client=oauth_client)



        orm_token = cls(
            generated=generated,
            note=note or '',
            client_id=client_id,
            session_id=session_id,
            scopes=list(scopes),
        )
        db.add(orm_token)
        orm_token.token = token
        if user:
            assert user.id is not None
            orm_token.user = user
        else:
            assert service.id is not None
            orm_token.service = service
        if expires_in:
            if not isinstance(expires_in, numbers.Real):
                raise TypeError(
                    f"expires_in must be a positive integer or null, not {expires_in!r}"
                )
            expires_in = int(expires_in)

            if expires_in < 1:
                raise ValueError(
                    f"expires_in must be a positive integer or null, not {expires_in!r}"
                )

            orm_token.expires_at = cls.now() + timedelta(seconds=expires_in)

        db.commit()
        return token

    def update_scopes(self, new_scopes):
        ''
        from .scopes import _check_scopes_exist, _check_token_scopes

        _check_scopes_exist(new_scopes, who_for="token")
        _check_token_scopes(
            new_scopes, owner=self.owner, oauth_client=self.oauth_client
        )
        self.scopes = new_scopes


class OAuthCode(Expiring, Base):
    __tablename__ = 'oauth_codes'

    id = Column(Integer, primary_key=True, autoincrement=True)
    client_id = Column(
        Unicode(255), ForeignKey('oauth_clients.identifier', ondelete='CASCADE')
    )
    client = relationship(
        "OAuthClient",
        back_populates="codes",
    )
    code = Column(Unicode(36))
    expires_at = Column(Integer)
    redirect_uri = Column(Unicode(1023))
    session_id = Column(Unicode(255))

    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'))
    user = relationship(
        "User",
        back_populates="oauth_codes",
    )

    scopes = Column(JSONList, default=[])

    @staticmethod
    def now():
        return utcnow(with_tz=True).timestamp()

    @classmethod
    def find(cls, db, code):
        return (
            db.query(cls)
            .filter(cls.code == code)
            .filter(or_(cls.expires_at == None, cls.expires_at >= cls.now()))
            .options(

                joinedload(cls.user, innerjoin=True),
            )
            .first()
        )

    def __repr__(self):
        return (
            f"<{self.__class__.__name__}(id={self.id}, client_id={self.client_id!r})>"
        )


class OAuthClient(Base):
    __tablename__ = 'oauth_clients'
    id = Column(Integer, primary_key=True, autoincrement=True)
    identifier = Column(Unicode(255), unique=True)
    description = Column(Unicode(1023))
    secret = Column(Unicode(255))
    redirect_uri = Column(Unicode(1023))

    @property
    def client_id(self):
        return self.identifier

    spawner = relationship(
        "Spawner",
        back_populates="oauth_client",
        uselist=False,
    )
    service = relationship(
        "Service",
        back_populates="oauth_client",
        uselist=False,
    )
    access_tokens = relationship(
        APIToken, back_populates='oauth_client', cascade='all, delete-orphan'
    )
    codes = relationship(
        OAuthCode, back_populates='client', cascade='all, delete-orphan'
    )



    allowed_scopes = Column(JSONList, default=[])

    def __repr__(self):
        return f"<{self.__class__.__name__}(identifier={self.identifier!r})>"





class DatabaseSchemaMismatch(Exception):
    ''





def register_foreign_keys(engine):
    ''

    @event.listens_for(engine, "connect")
    def connect(dbapi_con, con_record):
        cursor = dbapi_con.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


def _expire_relationship(target, relationship_prop):
    ''




    session = object_session(target)

    peers = getattr(target, relationship_prop.key)
    if peers is None:

        return


    if (
        relationship_prop.direction is interfaces.MANYTOONE
        or not relationship_prop.uselist
    ):
        peers = [peers]
    for obj in peers:
        if inspect(obj).persistent:
            session.expire(obj, [relationship_prop.back_populates])


@event.listens_for(Session, "persistent_to_deleted")
def _notify_deleted_relationships(session, obj):
    ''



    mapper = inspect(obj).mapper
    for prop in mapper.relationships:
        if prop.back_populates:
            _expire_relationship(obj, prop)


def register_ping_connection(engine):
    ''













    def ping_connection(connection):


        save_should_close_with_result = connection.should_close_with_result
        connection.should_close_with_result = False

        try:



            with connection.begin() as transaction:
                connection.scalar(select(1))
        except exc.DBAPIError as err:





            if err.connection_invalidated:
                app_log.error(
                    "Database connection error, attempting to reconnect: %s", err
                )




                with connection.begin() as transaction:
                    connection.scalar(select(1))
            else:
                raise
        finally:

            connection.should_close_with_result = save_should_close_with_result


    def ping_connection_v1(connection, branch=None):
        ''
        return ping_connection(connection)

    if int(sqlalchemy.__version__.split(".", 1)[0]) >= 2:
        listener = ping_connection
    else:
        listener = ping_connection_v1
    event.listens_for(engine, "engine_connect")(listener)


def check_db_revision(engine):
    ''









    current_table_names = set(inspect(engine).get_table_names())
    my_table_names = set(Base.metadata.tables.keys())

    from .dbutil import _temp_alembic_ini


    engine_url = engine.url.render_as_string(hide_password=False)

    with _temp_alembic_ini(engine_url) as ini:
        cfg = alembic.config.Config(ini)
        scripts = ScriptDirectory.from_config(cfg)
        head = scripts.get_heads()[0]
        base = scripts.get_base()

        if not my_table_names.intersection(current_table_names):

            app_log.debug("Stamping empty database with alembic revision %s", head)
            alembic.command.stamp(cfg, head)
            return

        if 'alembic_version' not in current_table_names:




            msg_t = "Database schema version not found, guessing that JupyterHub %s created this database."
            if 'spawners' in current_table_names:

                app_log.warning(msg_t, '0.8.dev')
                rev = head
            elif 'services' in current_table_names:

                app_log.warning(msg_t, '0.7.x')
                rev = 'af4cbdb2d13c'
            else:

                app_log.warning(msg_t, '0.6 or earlier')
                rev = base
            app_log.debug("Stamping database schema version %s", rev)
            alembic.command.stamp(cfg, rev)



    with engine.begin() as connection:
        alembic_revision = connection.execute(
            text('SELECT version_num FROM alembic_version')
        ).first()[0]
    if alembic_revision == head:
        app_log.debug("database schema version found: %s", alembic_revision)
    else:
        raise DatabaseSchemaMismatch(
            f"Found database schema version {alembic_revision} != {head}. "
            "Backup your database and run `jupyterhub upgrade-db`"
            " to upgrade to the latest schema."
        )


def mysql_large_prefix_check(engine):
    ''
    if not str(engine.url).startswith('mysql'):
        return False
    with engine.begin() as connection:
        variables = dict(
            connection.execute(
                text(
                    'show variables where variable_name like '
                    '"innodb_large_prefix" or '
                    'variable_name like "innodb_file_format";'
                )
            ).fetchall()
        )
    if (
        variables.get('innodb_file_format', 'Barracuda') == 'Barracuda'
        and variables.get('innodb_large_prefix', 'ON') == 'ON'
    ):
        return True
    else:
        return False


def add_row_format(base):
    for t in base.metadata.tables.values():
        t.dialect_kwargs['mysql_ROW_FORMAT'] = 'DYNAMIC'


def new_session_factory(
    url="sqlite:///:memory:", reset=False, expire_on_commit=False, **kwargs
):
    ''
    if url.startswith('sqlite'):
        kwargs.setdefault('connect_args', {'check_same_thread': False})

    elif url.startswith('mysql'):
        kwargs.setdefault('pool_recycle', 60)

    kwargs.setdefault("future", True)

    if url.endswith(':memory:'):


        kwargs.setdefault('poolclass', StaticPool)

    engine = create_engine(url, **kwargs)
    if url.startswith('sqlite'):
        register_foreign_keys(engine)


    register_ping_connection(engine)

    if reset:
        Base.metadata.drop_all(engine)

    if mysql_large_prefix_check(engine):
        add_row_format(Base)

    check_db_revision(engine)

    Base.metadata.create_all(engine)





    session_factory = sessionmaker(bind=engine, expire_on_commit=expire_on_commit)
    return session_factory


def get_class(resource_name):
    ''
    class_dict = {
        'users': User,
        'services': Service,
        'tokens': APIToken,
        'groups': Group,
    }
    if resource_name not in class_dict:
        raise ValueError(
            f'Kind must be one of {", ".join(class_dict)}, not {resource_name}'
        )
    return class_dict[resource_name]
