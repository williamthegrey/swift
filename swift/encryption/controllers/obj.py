__author__ = 'William'

from urllib import unquote, quote
from swift.common.utils import public
from swift.encryption.controllers.base import Controller, delay_denial, \
    redirected, path_encrypted
from swift.encryption.utils.encryptionutils import encrypt, decrypt
from base64 import urlsafe_b64encode as b64encode
import functools
from swift.common.utils import split_path


def obj_body_encrypted(func):
    """
    Decorator to encrypt a request body for an object controller method

    :param func: an object controller method to encrypt a request body for
    """

    @functools.wraps(func)
    def wrapped(*a, **kw):
        (controller, req) = a

        if controller.is_container_encrypted(req):
            # get encryption key
            key_id, key = controller.get_container_key(req)

            # encrypt object
            req.body = encrypt(key, req.body)
            req.body = key_id + req.body

        # call controller method
        return func(*a, **kw)
    return wrapped


def obj_body_decrypted(func):
    """
    Decorator to decrypt a response body for an object controller method

    :param func: an object controller method to decrypt a response body for
    """

    @functools.wraps(func)
    def wrapped(*a, **kw):
        (controller, req) = a
        # call controller method
        res = func(*a, **kw)

        if res.is_success and controller.is_container_encrypted(req):
            # extract encryption key id
            key_id = res.body[0:32]
            res.body = res.body[32:]

            # get encryption key
            key_id, key = controller.get_container_key(req, key_id=key_id)

            # decrypt object
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
        (controller, req) = a

        # get encryption key
        key_id, key = controller.get_account_key(req)

        # get origin destination path
        destination_path = unquote(req.environ['HTTP_DESTINATION'])

        # get encrypted destination path
        container, obj = split_path('/' + destination_path, 1, 2, True)
        destination_path_encrypted = quote(container, safe='')
        if obj:
            obj = b64encode(encrypt(key, obj))
            obj = quote(obj, safe='')
            destination_path_encrypted += '/' + obj

        # set destination path
        req.environ['HTTP_DESTINATION'] = destination_path_encrypted

        # call controller method
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

        res = self.forward_to_swift_proxy(req)
        return res

    @public
    @delay_denial
    @redirected
    @path_encrypted
    def HEAD(self, req):
        """Handler for HTTP HEAD requests."""

        res = self.forward_to_swift_proxy(req)
        return res

    @public
    @delay_denial
    @redirected
    @path_encrypted
    @obj_body_encrypted
    def PUT(self, req):
        """HTTP PUT request handler."""

        res = self.forward_to_swift_proxy(req)
        return res

    @public
    @delay_denial
    @redirected
    @path_encrypted
    def POST(self, req):
        """HTTP POST request handler."""

        res = self.forward_to_swift_proxy(req)
        return res

    @public
    @delay_denial
    @redirected
    @path_encrypted
    def DELETE(self, req):
        """HTTP DELETE request handler."""

        res = self.forward_to_swift_proxy(req)
        return res

    @public
    @delay_denial
    @redirected
    @path_encrypted
    @destination_encrypted
    def COPY(self, req):
        """HTTP COPY request handler."""

        res = self.forward_to_swift_proxy(req)
        return res
