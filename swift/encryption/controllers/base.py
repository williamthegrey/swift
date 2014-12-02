__author__ = 'William'

from urllib import unquote, quote
import inspect
from swift.common.utils import public
from swift.common.swob import Response
from swift import gettext_ as _
from swift.encryption.utils.encryptionutils import encrypt, decrypt
import functools


key = '0123456789abcdef0123456789abcdef'


def delay_denial(func):
    """
    Decorator to declare which methods should have any swift.authorize call
    delayed. This is so the method can load the Request object up with
    additional information that may be needed by the authorization system.

    :param func: function for which authorization will be delayed
    """
    func.delay_denial = True

    @functools.wraps(func)
    def wrapped(*a, **kw):
        return func(*a, **kw)
    return wrapped


def encrypted(func):
    """
    Decorator to encrypt a request body for a controller method

    :param func: a controller method to encrypt a request body for
    """

    @functools.wraps(func)
    def wrapped(*a, **kw):
        req = a[1]
        req.body = encrypt(key, req.body)
        return func(*a, **kw)
    return wrapped


def decrypted(func):
    """
    Decorator to decrypt a response body for a controller method

    :param func: a controller method to decrypt a response body for
    """

    @functools.wraps(func)
    def wrapped(*a, **kw):
        res = func(*a, **kw)
        res.body = decrypt(key, res.body)
        return res
    return wrapped


def update_headers(response, headers):
    """
    Helper function to update headers in the response.

    :param response: swob.Response object
    :param headers: dictionary headers
    """
    if hasattr(headers, 'items'):
        headers = headers.items()
    for name, value in headers:
        if name == 'etag':
            response.headers[name] = value.replace('"', '')
        elif name not in ('date', 'content-length', 'content-type',
                          'connection', 'x-put-timestamp', 'x-delete-after'):
            response.headers[name] = value


class Controller(object):
    """Base WSGI controller class for the encryption server"""
    server_type = 'Base'

    # Ensure these are all lowercase
    pass_through_headers = []

    def __init__(self, app):
        """
        Creates a controller attached to an application instance

        :param app: the application instance
        """
        self.account_name = None
        self.app = app
        self.trans_id = '-'
        self._allowed_methods = None

    @property
    def allowed_methods(self):
        if self._allowed_methods is None:
            self._allowed_methods = set()
            all_methods = inspect.getmembers(self, predicate=inspect.ismethod)
            for name, m in all_methods:
                if getattr(m, 'publicly_accessible', False):
                    self._allowed_methods.add(name)
        return self._allowed_methods
