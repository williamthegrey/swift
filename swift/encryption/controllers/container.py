__author__ = 'William'

from urllib import unquote, quote
from swift.common.utils import public, config_true_value
from swift.encryption.controllers.base import Controller, delay_denial, \
    update_headers, redirected, path_encrypted
from swift import gettext_ as _
from swift.encryption.utils.encryptionutils import encrypt, decrypt
from base64 import urlsafe_b64encode as b64encode, urlsafe_b64decode as b64decode
import functools
from swift.common.utils import split_path
from swift.encryption.api.kms_api import kms_api


def container_body_decrypted(func):
    """
    Decorator to decrypt a response body for an container controller method

    :param func: an container controller method to decrypt a response body for
    """

    @functools.wraps(func)
    def wrapped(*a, **kw):
        # TODO: support json format
        (controller, req) = a

        # call controller method
        res = func(*a, **kw)

        # get encryption key
        key_id, key = controller.get_account_key(req)

        # decrypt response body
        objects = res.body.splitlines()
        body_decrypted = ""
        for obj in objects:
            obj_decrypted = decrypt(key, b64decode(obj))
            body_decrypted += obj_decrypted + '\n'
        res.body = body_decrypted

        return res
    return wrapped


class ContainerController(Controller):
    """WSGI controller for object requests."""
    server_type = 'Container'

    def __init__(self, app, account_name, container_name, object_name,
                 **kwargs):
        Controller.__init__(self, app)
        self.account_name = unquote(account_name)
        self.container_name = unquote(container_name)

    @public
    @delay_denial
    @redirected
    @path_encrypted
    @container_body_decrypted
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
