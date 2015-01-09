__author__ = 'William'

from urllib import unquote, quote
from swift.common.utils import public, config_true_value, split_path
from swift.encryption.controllers.base import Controller, delay_denial, \
    update_headers, redirected, path_encrypted
from swift import gettext_ as _
from swift.encryption.utils.encryptionutils import encrypt, decrypt
from base64 import urlsafe_b64encode as b64encode, urlsafe_b64decode as b64decode
import functools
from swift.encryption.api.kms_api import kms_api
from swift.common.utils import split_path


def obj_body_encrypted(func):
    """
    Decorator to encrypt a request body for an object controller method

    :param func: an object controller method to encrypt a request body for
    """

    @functools.wraps(func)
    def wrapped(*a, **kw):
        (controller, req) = a

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
