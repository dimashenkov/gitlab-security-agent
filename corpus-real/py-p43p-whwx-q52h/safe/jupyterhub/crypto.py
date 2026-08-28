import base64
import json
import os
from binascii import a2b_hex
from concurrent.futures import ThreadPoolExecutor

from traitlets import Any, Integer, List, default, observe, validate
from traitlets.config import Config, SingletonConfigurable

try:
    import cryptography
    from cryptography.fernet import Fernet, InvalidToken, MultiFernet
except ImportError:
    cryptography = None

    class InvalidToken(Exception):
        pass


from .utils import maybe_future

KEY_ENV = 'JUPYTERHUB_CRYPT_KEY'


class EncryptionUnavailable(Exception):
    pass


class CryptographyUnavailable(EncryptionUnavailable):
    def __str__(self):
        return "cryptography library is required for encryption"


class NoEncryptionKeys(EncryptionUnavailable):
    def __str__(self):
        return f"Encryption keys must be specified in {KEY_ENV} env"


def _validate_key(key):
    ''











    if isinstance(key, str):
        key = key.encode('ascii')

    if len(key) == 44:
        try:
            key = base64.urlsafe_b64decode(key)
        except ValueError:
            pass

    elif len(key) == 64:
        try:

            return a2b_hex(key)
        except ValueError:

            pass

    if len(key) != 32:
        raise ValueError("Encryption keys must be 32 bytes, hex or base64-encoded.")

    return key


class CryptKeeper(SingletonConfigurable):
    ''




    n_threads = Integer(
        max(os.cpu_count(), 1),
        config=True,
        help="The number of threads to allocate for encryption",
    )

    @default('config')
    def _config_default(self):

        from .app import JupyterHub

        if JupyterHub.initialized():
            return JupyterHub.instance().config
        else:
            return Config()

    executor = Any()

    def _executor_default(self):
        return ThreadPoolExecutor(self.n_threads)

    keys = List(config=True)

    def _keys_default(self):
        if KEY_ENV not in os.environ:
            return []


        return [
            _validate_key(key) for key in os.environ[KEY_ENV].split(';') if key.strip()
        ]

    @validate('keys')
    def _ensure_bytes(self, proposal):

        return [_validate_key(key) for key in proposal.value]

    fernet = Any()

    def _fernet_default(self):
        if cryptography is None or not self.keys:
            return None
        return MultiFernet([Fernet(base64.urlsafe_b64encode(key)) for key in self.keys])

    @observe('keys')
    def _update_fernet(self, change):
        self.fernet = self._fernet_default()

    def check_available(self):
        if cryptography is None:
            raise CryptographyUnavailable()
        if not self.keys:
            raise NoEncryptionKeys()

    def _encrypt(self, data):
        ''




        return self.fernet.encrypt(json.dumps(data).encode('utf8'))

    def encrypt(self, data):
        ''
        self.check_available()
        return maybe_future(self.executor.submit(self._encrypt, data))

    def _decrypt(self, encrypted):
        decrypted = self.fernet.decrypt(encrypted)
        return json.loads(decrypted.decode('utf8'))

    def decrypt(self, encrypted):
        ''
        self.check_available()
        return maybe_future(self.executor.submit(self._decrypt, encrypted))


def encrypt(data):
    ''




    return CryptKeeper.instance().encrypt(data)


def decrypt(data):
    ''



    return CryptKeeper.instance().decrypt(data)
