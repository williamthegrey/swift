__author__ = 'William'

from urllib import unquote, quote
from swift.common.utils import public
from swift.encryption.controllers.base import Controller, delay_denial, \
    redirected, path_encrypted, EncryptedAccessException
from base64 import urlsafe_b64encode as b64encode
import functools
from swift.common.utils import split_path
from Crypto.PublicKey import RSA


def obj_body_encrypted(func):
    """
    Decorator to encrypt a request body for an object controller method

    :param func: an object controller method to encrypt a request body for
    """

    @functools.wraps(func)
    def wrapped(*a, **kw):
        (controller, req) = a

        if controller.is_container_encrypted(req):
            # set object owner
            req.environ['HTTP_X_OBJECT_META_OWNER'] = req.environ['HTTP_X_USER_ID']
            # encrypt object
            cipher = controller.get_cipher(req)
            msg_dict = cipher.encrypt_sign(req.body)
            req.body = msg_dict['signature'] + msg_dict['msg']

            # put encryption key
            controller.put_object_key(req, msg_dict['key'][0])

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
            # get encryption key
            key = controller.get_object_key(req)
            if not key:
                raise EncryptedAccessException(req.method, req.path, 'Not authorized')
            ext_pub_key = None
            user_id = req.environ['HTTP_X_USER_ID']
            if 'X-Object-Meta-Owner' in res.headers \
                    and res.headers['X-Object-Meta-Owner'] != user_id:
                ext_pub_key = controller.get_user_key(req, res.headers['X-Object-Meta-Owner'])
                ext_pub_key = RSA.importKey(ext_pub_key)

            cipher = controller.get_cipher(req)
            res.body = cipher.verify_decrypt(res.body[256:], res.body[0:256], key, ext_pub_key)

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

        # get origin destination path
        destination_path = unquote(req.environ['HTTP_DESTINATION'])
        container, obj = split_path('/' + destination_path, 1, 2, True)

        if obj and controller.is_container_encrypted(req):
            # get encryption key
            key = controller.get_container_key(req)

            # encrypt destination path
            destination_path_encrypted = container
            cipher = controller.get_cipher(req)
            obj = b64encode(cipher.encrypt(obj, key))
            destination_path_encrypted += '/' + obj
            destination_path_encrypted = quote(destination_path_encrypted)

            # set destination path
            req.environ['HTTP_DESTINATION'] = destination_path_encrypted

            # TODO: copy key

            # call controller method
            res = func(*a, **kw)

            # reset path
            req.environ['HTTP_DESTINATION'] = destination_path
        else:
            # call controller method
            res = func(*a, **kw)

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

        # TODO: get rid of original file name

        te = req.environ.get('HTTP_TRANSFER_ENCODING', None)
        ae = req.environ.get('HTTP_ACCEPT_ENCODING', None)

        # disable chunked transfer
        if te == 'chunked':
            del req.environ['HTTP_TRANSFER_ENCODING']
            del req.environ['HTTP_ACCEPT_ENCODING']

            res = self.forward_to_swift_proxy(req)

            req.environ['HTTP_TRANSFER_ENCODING'] = te
            req.environ['HTTP_ACCEPT_ENCODING'] = ae

        else:
            res = self.forward_to_swift_proxy(req)

        return res

    @public
    @delay_denial
    @redirected
    @path_encrypted
    def POST(self, req):
        """HTTP POST request handler."""

        if 'HTTP_X_SHARED_USER_ID' in req.environ:
            return self.share(req, 'object')

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
