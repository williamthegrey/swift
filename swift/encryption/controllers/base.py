__author__ = 'William'

from urllib import unquote, quote
import inspect
from swift.common.utils import public
from swift.common.swob import Request, Response
from swift.encryption.api import swift_api
from django.utils.encoding import force_unicode
from django.utils.translation import ugettext_lazy as _
from horizon import exceptions
from swift.encryption.utils.encryptionutils import encrypt, decrypt
import functools

key = '0123456789abcdef0123456789abcdef'


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


class Controller(object):
    """Base WSGI controller class for the encryption server"""
    server_type = 'Base'

    # Ensure these are all lowercase
    pass_through_headers = []

    def __init__(self, app, account_name, container_name, object_name,
                 **kwargs):
        """
        Creates a controller attached to an application instance

        :param app: the application instance
        """
        self.app = app
        self.trans_id = '-'
        self._allowed_methods = None

        self.account_name = unquote(account_name)
        self.container_name = unquote(container_name)
        self.object_name = unquote(object_name)

    @property
    def allowed_methods(self):
        if self._allowed_methods is None:
            self._allowed_methods = set()
            all_methods = inspect.getmembers(self, predicate=inspect.ismethod)
            for name, m in all_methods:
                if getattr(m, 'publicly_accessible', False):
                    self._allowed_methods.add(name)
        return self._allowed_methods

    @public
    @decrypted
    def GET(self, req):
        """
        Handler for HTTP GET requests.

        :param req: The client request
        :returns: the response to the client
        """
        return self.GETorHEAD(req)

    @public
    def HEAD(self, req):
        """
        Handler for HTTP HEAD requests.

        :param req: The client request
        :returns: the response to the client
        """
        return self.GETorHEAD(req)

    @public
    def OPTIONS(self, req):
        """
        Base handler for OPTIONS requests

        :param req: swob.Request object
        :returns: swob.Response object
        """
        pass

    def GETorHEAD(self, req):
        try:
            obj = swift_api.swift_get_object(req, self.container_name, self.object_name)
            msg = _("Object was successfully downloaded.")
            #messages.success(request, msg)
        except Exception as e:
            exceptions.handle(req, _("Unable to download object."))

        res = Response(request=req)
        res.etag = obj.get('_apidict', None)['etag']
        res.body = obj.data

        return res

    @public
    @encrypted
    def PUT(self, req):
        """HTTP PUT request handler."""

        try:
            obj = swift_api.swift_upload_object(req,
                                                self.container_name,
                                                self.object_name,
                                                req.body)
            msg = _("Object was successfully uploaded.")
            #messages.success(request, msg)
        except Exception as e:
            exceptions.handle(req, _("Unable to upload object."))

        res = Response(request=req)
        #res.environ['Last-Modified'] =
        res.environ['CONTENT_LENGTH'] = 0
        #res.environ['HTTP_X_TRANS_ID'] = req.environ['swift.trans_id']
        res.etag = obj.get('_apidict', None)['etag']

        return res

    @public
    def POST(self, req):
        """HTTP POST request handler."""
        pass

    @public
    def DELETE(self, req):
        """HTTP DELETE request handler."""
        pass
