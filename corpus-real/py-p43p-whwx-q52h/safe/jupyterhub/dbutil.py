''




import os
import shutil
import sys
from contextlib import contextmanager
from datetime import datetime
from subprocess import check_call
from tempfile import TemporaryDirectory
from urllib.parse import urlparse

from sqlalchemy import create_engine

from . import orm

_here = os.path.abspath(os.path.dirname(__file__))

ALEMBIC_INI_TEMPLATE_PATH = os.path.join(_here, 'alembic.ini')
ALEMBIC_DIR = os.path.join(_here, 'alembic')


def write_alembic_ini(alembic_ini='alembic.ini', db_url='sqlite:///jupyterhub.sqlite'):
    ''








    with open(ALEMBIC_INI_TEMPLATE_PATH) as f:
        alembic_ini_tpl = f.read()

    with open(alembic_ini, 'w') as f:
        f.write(
            alembic_ini_tpl.format(
                alembic_dir=ALEMBIC_DIR,




                db_url=str(db_url).replace('%', '%%'),
            )
        )


@contextmanager
def _temp_alembic_ini(db_url):
    ''
















    with TemporaryDirectory() as td:
        alembic_ini = os.path.join(td, 'alembic.ini')
        write_alembic_ini(alembic_ini, db_url)
        yield alembic_ini


def upgrade(db_url, revision='head'):
    ''






    with _temp_alembic_ini(db_url) as alembic_ini:
        check_call(['alembic', '-c', alembic_ini, 'upgrade', revision])


def backup_db_file(db_file, log=None):
    ''
    timestamp = datetime.now().strftime('.%Y-%m-%d-%H%M%S')
    backup_db_file = db_file + timestamp
    for i in range(1, 10):
        if not os.path.exists(backup_db_file):
            break
        backup_db_file = f'{db_file}.{timestamp}.{i}'

    if os.path.exists(backup_db_file):
        raise OSError(f"backup db file already exists: {backup_db_file}")
    if log:
        log.info("Backing up %s => %s", db_file, backup_db_file)
    shutil.copy(db_file, backup_db_file)


def upgrade_if_needed(db_url, *, db_kwargs=None, backup=True, log=None):
    ''





    engine = create_engine(db_url, **db_kwargs or {})
    try:
        orm.check_db_revision(engine)
    except orm.DatabaseSchemaMismatch:

        pass
    else:

        return
    urlinfo = urlparse(db_url)
    if urlinfo.password:

        urlinfo = urlinfo._replace(
            netloc=f'{urlinfo.username}:[redacted]@{urlinfo.hostname}:{urlinfo.port}'
        )
        db_log_url = urlinfo.geturl()
    else:
        db_log_url = db_url
    log.info("Upgrading %s", db_log_url)

    if backup and db_url.startswith('sqlite:///'):
        db_file = db_url.split(':///', 1)[1]
        backup_db_file(db_file, log=log)
    upgrade(db_url)


def shell(args=None):
    ''
    from .app import JupyterHub

    hub = JupyterHub()
    hub.load_config_file(hub.config_file)
    db_url = hub.db_url
    db = orm.new_session_factory(db_url, **hub.db_kwargs)()
    ns = {'db': db, 'db_url': db_url, 'orm': orm}

    import IPython

    IPython.start_ipython(args, user_ns=ns)


def _alembic(args):
    ''
    from .app import JupyterHub

    hub = JupyterHub()
    hub.load_config_file(hub.config_file)
    db_url = hub.db_url
    with _temp_alembic_ini(db_url) as alembic_ini:
        check_call(['alembic', '-c', alembic_ini] + args)


def main(args=None):
    if args is None:
        args = sys.argv[1:]


    choices = ['shell', 'alembic']
    if not args or args[0] not in choices:
        print("Select a command from: {}".format(', '.join(choices)))
        return 1
    cmd, args = args[0], args[1:]

    if cmd == 'shell':
        shell(args)
    elif cmd == 'alembic':
        _alembic(args)


if __name__ == '__main__':
    sys.exit(main())
