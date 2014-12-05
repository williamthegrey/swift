__author__ = 'William'

from urllib import unquote, quote
from swift.common.utils import public
from swift.encryption.controllers.base import Controller, delay_denial, \
    update_headers, redirected, path_encrypted
from swift import gettext_ as _
from swift.encryption.api import swift_api
from swift.encryption.utils.encryptionutils import encrypt, decrypt
from base64 import b64encode, b64decode
import functools


key = '0123456789abcdef0123456789abcdef'


def account_body_decrypted(func):
    """
    Decorator to decrypt a response body for an account controller method

    :param func: an account controller method to decrypt a response body for
    """

    @functools.wraps(func)
    def wrapped(*a, **kw):
        # TODO: support json format
        res = func(*a, **kw)
        containers = res.body.splitlines()
        body_decrypted = ""
        for container in containers:
            container_decrypted = decrypt(key, b64decode(container))
            body_decrypted += container_decrypted + '\n'
        res.body = body_decrypted
        return res
    return wrapped


class AccountController(Controller):
    """WSGI controller for object requests."""
    server_type = 'Account'

    def __init__(self, app, account_name, container_name, object_name,
                 **kwargs):
        Controller.__init__(self, app)
        self.account_name = unquote(account_name)

    @public
    @delay_denial
    @redirected
    @path_encrypted
    @account_body_decrypted
    def GET(self, req):
        """Handler for HTTP GET requests."""

        res = self.get_working_response(req)
        return res

    @public
    @delay_denial
    @redirected
    @path_encrypted
    def HEAD(self, req):
        """Handler for HTTP HEAD requests."""

        res = self.get_working_response(req)
        return res

    @public
    @delay_denial
    @redirected
    @path_encrypted
    def POST(self, req):
        """HTTP POST request handler."""

        res = self.get_working_response(req)
        return res
