__author__ = 'William'

import inspect
from urllib import unquote
from swift.encryption.utils.encryptionutils import encrypt
from swift.common.utils import split_path
from swift.encryption.utils.httputils import get_working_response
import functools
from base64 import urlsafe_b64encode as b64encode
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

        # call controller method
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
        (controller, req) = a

        # get encryption key
        key_id, key = controller.get_account_key(req)

        # get origin path
        path_info = unquote(req.path)
        version, account, container, obj = split_path(path_info, 2, 4, True)

        # encrypt path
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

        # call controller method
        res = func(*a, **kw)

        # reset path
        res.environ['PATH_INFO'] = path_info
        res.environ['RAW_PATH_INFO'] = path_info

        return res
    return wrapped


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

    def forward_to_swift_proxy(self, req):
        conn_timeout = self.app.conn_timeout
        proxy_timeout = self.app.proxy_timeout
        return get_working_response(req, conn_timeout, proxy_timeout)

    def get_kms_api(self):
        kms_host = self.app.kms_host
        kms_port = self.app.kms_port
        kms_timeout = self.app.kms_timeout
        conn_timeout = self.app.conn_timeout

        return kms_api(kms_host, kms_port, conn_timeout, kms_timeout)

    @staticmethod
    def get_key_path(req, key_type):
        if key_type != 'account' and key_type != 'container':
            return None

        path = unquote(req.path)
        if key_type == 'account':
            version, account, container, obj = split_path(path, 2, 4, True)
            key_path = '/' + '/'.join([version, account])
        elif key_type == 'container':
            version, account, container, obj = split_path(path, 3, 4, True)
            key_path = '/' + '/'.join([version, account, container])
        else:
            key_path = None

        return key_path

    def get_key(self, req, key_type, key_id=None):
        kms_connection = self.get_kms_api()
        key_path = self.get_key_path(req, key_type)
        token = req.environ['HTTP_X_AUTH_TOKEN']
        return kms_connection.get_key(key_path, token, key_id)

    def get_account_key(self, req, key_id=None):
        return self.get_key(req, 'account', key_id)

    def get_container_key(self, req, key_id=None):
        return self.get_key(req, 'container', key_id)
