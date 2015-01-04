__author__ = 'William'

import inspect
from urllib import unquote, quote
from swift.common.utils import public
from swift.common.swob import Response
from swift import gettext_ as _
from swift.encryption.utils.encryptionutils import encrypt, decrypt
from swift.common.utils import split_path, config_true_value
from swift.common.bufferedhttp import http_connect_raw
from eventlet.timeout import Timeout
from swift.common.http import HTTP_OK, HTTP_PARTIAL_CONTENT
from swift.common.exceptions import ConnectionTimeout
import functools
from base64 import b64encode, b64decode
from swift.encryption.api.kms_api import kms_api


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


def redirected(func):
    """
    Decorator to redirect a request and its response for a controller method

    :param func: a controller method to redirect requests and responses for
    """

    @functools.wraps(func)
    def wrapped(*a, **kw):
        controller = a[0]
        app = controller.app
        proxy_host = app.proxy_host
        proxy_port = app.proxy_port

        req = a[1]
        remote_addr = req.environ['REMOTE_ADDR']
        remote_port = req.environ['REMOTE_PORT']
        http_host = req.environ['HTTP_HOST']
        server_name = req.environ['SERVER_NAME']
        server_port = req.environ['SERVER_PORT']

        # change remote
        req.environ['REMOTE_ADDR'] = server_name

        # change server
        req.environ['HTTP_HOST'] = proxy_host + ":" + proxy_port
        req.environ['SERVER_NAME'] = proxy_host
        req.environ['SERVER_PORT'] = proxy_port

        # call controller
        res = func(*a, **kw)

        # reset remote
        res.environ['REMOTE_ADDR'] = remote_addr
        req.environ['REMOTE_PORT'] = remote_port

        # reset server
        req.environ['HTTP_HOST'] = http_host
        req.environ['SERVER_NAME'] = server_name
        req.environ['SERVER_PORT'] = server_port

        return res
    return wrapped


def path_encrypted(func):
    """
    Decorator to encrypt the path for a controller method

    :param func: a controller method to encrypt the path for
    """

    @functools.wraps(func)
    def wrapped(*a, **kw):
        app = a[0].app
        kms_host = app.kms_host
        kms_port = app.kms_port
        kms_timeout = app.kms_timeout
        conn_timeout = app.conn_timeout

        req = a[1]
        token = req.environ['HTTP_X_AUTH_TOKEN']

        path_info = req.path
        version, account, container, obj = split_path(unquote(path_info), 1, 4, True)
        key_path = '/' + '/'.join([version, account])
        key_id, key = kms_api(kms_host, kms_port, conn_timeout, kms_timeout).get_key(key_path, token, key_id=None)

        # get encrypted path
        path_info_encrypted = "/" + version + "/" + account
        if container:
            container = b64encode(encrypt(key, container))
            path_info_encrypted += "/" + container
        if obj:
            obj = b64encode(encrypt(key, obj))
            path_info_encrypted += "/" + obj

        # set path
        req.environ['PATH_INFO'] = path_info_encrypted
        req.environ['RAW_PATH_INFO'] = path_info_encrypted

        # call controller
        res = func(*a, **kw)

        # reset path
        res.environ['PATH_INFO'] = path_info
        res.environ['RAW_PATH_INFO'] = path_info

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

    def get_working_response(self, req):
        source = self._get_source(req)
        res = None
        if source:
            res = Response(request=req)
            res.body = source.read()
            source.nuke_from_orbit()

            if req.method == 'GET' and \
                    source.status in (HTTP_OK, HTTP_PARTIAL_CONTENT):
                # See NOTE: swift_conn at top of file about this.
                res.swift_conn = source.swift_conn
            res.status = source.status
            update_headers(res, source.getheaders())
            if not res.environ:
                res.environ = {}
            res.environ['swift_x_timestamp'] = \
                source.getheader('x-timestamp')
            res.accept_ranges = 'bytes'
            res.content_length = source.getheader('Content-Length')
            if source.getheader('Content-Type'):
                res.charset = None
                res.content_type = source.getheader('Content-Type')

        return res

    def _get_source(self, req):
        proxy_timeout = self.app.proxy_timeout
        newest = config_true_value(req.headers.get('x-newest', 'f'))
        if self.server_type == 'Object' and not newest:
            proxy_timeout = self.app.recoverable_proxy_timeout

        server = {'ip': req.environ['SERVER_NAME'], 'port': req.environ['SERVER_PORT']}

        try:
            with ConnectionTimeout(self.app.conn_timeout):
                conn = http_connect_raw(
                    server['ip'], server['port'], req.method,
                    req.path, req.headers, req.query_string)

            with Timeout(proxy_timeout):
                conn.send(req.body)
                possible_source = conn.getresponse()
                # See NOTE: swift_conn at top of file about this.
                possible_source.swift_conn = conn
        except (Exception, Timeout) as e:
            self.app.exception_occurred(
                server, self.server_type,
                _('Trying to %(method)s %(path)s') %
                {'method': req.method, 'path': req.path})

        # TODO: best response
        source = possible_source

        return source
