from urllib import unquote
from swift.common.utils import public
from swift.encryption.controllers.base import Controller, delay_denial, \
    redirected, path_encrypted, EncryptedAccessException
from base64 import urlsafe_b64decode as b64decode
import functools
import json


def container_body_decrypted(func):
    """
    Decorator to decrypt a response body for an container controller method

    :param func: an container controller method to decrypt a response body for
    """

    @functools.wraps(func)
    def wrapped(*a, **kw):
        (controller, req) = a

        # call controller method
        res = func(*a, **kw)

        if controller.is_container_encrypted(req):
            # get encryption key
            key = controller.get_container_key(req)
            if not key:
                raise EncryptedAccessException(req.method, req.path, 'Not authorized')

            # decrypt response body
            res_format = req.params.get('format', 'plain')
            if res_format == 'json':
                objects = json.loads(res.body)
                for obj in objects:
                    obj_name = obj[u'name'].encode(res.charset)
                    cipher = controller.get_cipher(req)
                    obj_name = cipher.decrypt(b64decode(obj_name), key)
                    obj[u'name'] = unicode(obj_name, res.charset)
                res.body = json.dumps(objects)
            elif res_format == 'xml':
                # TODO: support xml
                pass
            elif res_format == 'plain':
                objects = res.body.splitlines()
                body_decrypted = ""
                for obj in objects:
                    cipher = controller.get_cipher(req)
                    obj_decrypted = cipher.decrypt(b64decode(obj), key)
                    body_decrypted += obj_decrypted + '\n'
                res.body = body_decrypted
            else:
                return res

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
    def PUT(self, req):
        """HTTP PUT request handler."""

        if 'HTTP_X_CONTAINER_META_ENCRYPTED' in req.environ \
                and req.environ['HTTP_X_CONTAINER_META_ENCRYPTED'] in ('True', 'true'):
            cipher = self.get_cipher(req)
            key = cipher.generate_key()

            self.put_container_key(req, key[0])

        res = self.forward_to_swift_proxy(req)
        return res

    @public
    @delay_denial
    @redirected
    @path_encrypted
    def POST(self, req):
        """HTTP POST request handler."""

        if 'HTTP_X_SHARED_USER_ID' in req.environ:
            return self.share(req, 'container')

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
