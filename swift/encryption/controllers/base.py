__author__ = 'William'

from urllib import unquote, quote
import inspect
from swift.common.utils import public
from swift.common.swob import Request, Response
from swift.encryption.api import swift_api
from django.utils.encoding import force_unicode
from django.utils.translation import ugettext_lazy as _
from horizon import exceptions


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
        res = Response(request=req)
        res.body = "Hello!\n"
        res.body += req.body
        res.body += "\n"

        return res

    @public
    def PUT(self, req):
        """HTTP PUT request handler."""

        object_file = req.body
        try:
            obj = swift_api.swift_upload_object(req,
                                                self.container_name,
                                                self.object_name,
                                                object_file)
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
