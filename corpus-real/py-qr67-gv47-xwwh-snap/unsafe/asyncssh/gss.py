



















''

import sys

from typing import Optional

from .misc import BytesOrStrDict


try:
    # pylint: disable=unused-import

    if sys.platform == 'win32': # pragma: no cover
        from .gss_win32 import GSSBase, GSSClient, GSSServer, GSSError
    else:
        from .gss_unix import GSSBase, GSSClient, GSSServer, GSSError

    gss_available = True
except ImportError: # pragma: no cover
    gss_available = False

    class GSSError(ValueError): # type: ignore
        ''

        def __init__(self, maj_code: int, min_code: int,
                 token: Optional[bytes] = None):
            super().__init__('GSS not available')

            self.maj_code = maj_code
            self.min_code = min_code
            self.token = token

    class GSSBase: # type: ignore
        ''

    class GSSClient(GSSBase): # type: ignore
        ''

        def __init__(self, _host: str, _store: Optional[BytesOrStrDict],
                     _delegate_creds: bool):
            raise GSSError(0, 0)

    class GSSServer(GSSBase): # type: ignore
        ''

        def __init__(self, _host: str, _store: Optional[BytesOrStrDict]):
            raise GSSError(0, 0)
