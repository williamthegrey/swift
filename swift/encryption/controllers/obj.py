__author__ = 'William'

from urllib import unquote, quote
from swift.common.utils import public, config_true_value, split_path
from swift.encryption.controllers.base import Controller, delay_denial, \
    update_headers, redirected, path_encrypted
from swift import gettext_ as _
from swift.encryption.api import swift_api
from swift.encryption.utils.encryptionutils import encrypt, decrypt
from base64 import b64encode, b64decode
import functools


key = '0123456789abcdef0123456789abcdef'


def obj_body_encrypted(func):
    """
    Decorator to encrypt a request body for an object controller method

    :param func: an object controller method to encrypt a request body for
    """

    @functools.wraps(func)
    def wrapped(*a, **kw):
        req = a[1]
        req.body = encrypt(key, req.body)
        return func(*a, **kw)
    return wrapped


def obj_body_decrypted(func):
    """
    Decorator to decrypt a response body for an object controller method

    :param func: an object controller method to decrypt a response body for
    """

    @functools.wraps(func)
    def wrapped(*a, **kw):
        res = func(*a, **kw)
        res.body = decrypt(key, res.body)
        return res
    return wrapped


def destination_encrypted(func):
    """
    Decorator to encrypt the copy destination for an object controller method

    :param func: an object controller method to encrypt the copy destination for
    """

    @functools.wraps(func)
    def wrapped(*a, **kw):
        req = a[1]
        destination_path = req.environ['HTTP_DESTINATION']

        # get encrypted destination path
        container, obj = split_path('/' + destination_path, 1, 2, True)
        destination_path_encrypted = ""
        if container:
            container = b64encode(encrypt(key, container))
            container = quote(container, safe='')
            destination_path_encrypted += container
        if obj:
            obj = b64encode(encrypt(key, obj))
            obj = quote(obj, safe='')
            destination_path_encrypted += "/" + obj


        # set destination path
        req.environ['HTTP_DESTINATION'] = destination_path_encrypted

        # call controller
        res = func(*a, **kw)

        # reset path
        req.environ['HTTP_DESTINATION'] = destination_path

        return res
    return wrapped


class ObjectController(Controller):
    """WSGI controller for object requests."""
    server_type = 'Object'

    def __init__(self, app, account_name, container_name, object_name,
                 **kwargs):
        Controller.__init__(self, app)
        self.account_name = unquote(account_name)
        self.container_name = unquote(container_name)
        self.object_name = unquote(object_name)

    @public
    @delay_denial
    @redirected
    @path_encrypted
    @obj_body_decrypted
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
    @obj_body_encrypted
    def PUT(self, req):
        """HTTP PUT request handler."""

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

    @public
    @delay_denial
    @redirected
    @path_encrypted
    def DELETE(self, req):
        """HTTP DELETE request handler."""

        res = self.get_working_response(req)
        return res

    @public
    @delay_denial
    @redirected
    @path_encrypted
    @destination_encrypted
    def COPY(self, req):
        """HTTP COPY request handler."""

        res = self.get_working_response(req)
        return res
