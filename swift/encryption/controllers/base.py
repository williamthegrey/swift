import inspect
from urllib import unquote
from swift.encryption.utils.encryptionutils import CompositeCipher
from swift.common.utils import split_path
from swift.encryption.utils.httputils import get_working_response
import functools
from base64 import urlsafe_b64encode as b64encode, b64decode
from swift.encryption.api.kms_api import kms_api
from swift.encryption.api.swift_api import swift_api
from eventlet.timeout import Timeout


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

        # get origin path
        path_info = unquote(req.path)
        version, account, container, obj = split_path(path_info, 2, 4, True)

        if obj and controller.is_container_encrypted(req):
            # get encryption key
            key = controller.get_container_key(req)
            if not key:
                raise EncryptedAccessException(req.method, req.path, 'Not authorized')

            # encrypt path
            path_info_encrypted = '/' + '/'.join([version, account, container])
            local_key_path = controller.get_local_key_path(req)
            cipher = CompositeCipher(local_key_path)
            obj = cipher.encrypt(obj, key)
            obj = b64encode(obj)

            # check encrypted obj path
            obj = controller.check_path(req, obj)

            # set path
            path_info_encrypted += '/' + obj
            req.environ['PATH_INFO'] = path_info_encrypted
            req.environ['RAW_PATH_INFO'] = path_info_encrypted

            # call controller method
            res = func(*a, **kw)

            # reset path
            res.environ['PATH_INFO'] = path_info
            res.environ['RAW_PATH_INFO'] = path_info
        else:
            # call controller method
            res = func(*a, **kw)

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
        try:
            res = get_working_response(req, conn_timeout, proxy_timeout)
        except Timeout:
            raise ForwardException(req.method, req.path, 'timeout')

        return res

    def get_kms_api(self):
        kms_host = self.app.kms_host
        kms_port = self.app.kms_port
        kms_timeout = self.app.kms_timeout
        conn_timeout = self.app.conn_timeout

        return kms_api(kms_host, kms_port, conn_timeout, kms_timeout)

    @staticmethod
    def build_key_path(req, key_type):
        user_id = req.environ['HTTP_X_USER_ID']

        if key_type != 'user' and key_type != 'container' and key_type != 'object':
            return None

        path = unquote(req.path)
        if key_type == 'user':
            version, account, container, obj = split_path(path, 2, 4, True)
            key_path = '/' + '/'.join([version, account, user_id])
        elif key_type == 'container':
            version, account, container, obj = split_path(path, 3, 4, True)
            key_path = '/' + '/'.join([version, account, user_id, container])
        elif key_type == 'object':
            version, account, container, obj = split_path(path, 4, 4, True)
            key_path = '/' + '/'.join([version, account, user_id, container, obj])
        else:
            key_path = None

        return key_path

    def get_local_key_path(self, req):
        user_id = req.environ['HTTP_X_USER_ID']
        local_key_path = self.app.local_key_dir + user_id + '.pem'
        return local_key_path

    def get_key(self, req, key_type):
        kms_connection = self.get_kms_api()
        key_path = self.build_key_path(req, key_type)
        token = req.environ['HTTP_X_AUTH_TOKEN']
        return kms_connection.get_key(key_path, token)

    def get_user_key(self, req):
        return self.get_key(req, 'user')

    def get_container_key(self, req):
        return self.get_key(req, 'container')

    def get_object_key(self, req):
        return self.get_key(req, 'object')

    def put_key(self, req, key_type, key):
        kms_connection = self.get_kms_api()
        key_path = self.build_key_path(req, key_type)
        token = req.environ['HTTP_X_AUTH_TOKEN']
        return kms_connection.put_key(key_path, key, token)

    def put_user_key(self, req, key):
        return self.put_key(req, 'user', key)

    def put_container_key(self, req, key):
        return self.put_key(req, 'container', key)

    def put_object_key(self, req, key):
        return self.put_key(req, 'object', key)

    def is_container_encrypted(self, req):
        swift_connection = swift_api(self.app.proxy_host, self.app.proxy_port,
                                     self.app.conn_timeout, self.app.proxy_timeout)
        path = unquote(req.path)
        version, account, container, obj = split_path(path, 3, 4, True)
        path = '/' + '/'.join([version, account, container])
        token = req.environ['HTTP_X_AUTH_TOKEN']

        headers = swift_connection.head(path, token)
        if 'X-Container-Meta-Encrypted' in headers and headers['X-Container-Meta-Encrypted'] in ('True', 'true'):
            return True

        else:
            return False

    def check_path(self, req, obj_intended):
        swift_connection = swift_api(self.app.proxy_host, self.app.proxy_port,
                                     self.app.conn_timeout, self.app.proxy_timeout)
        path = unquote(req.path)
        version, account, container, obj = split_path(path, 4, 4, True)
        path = '/' + '/'.join([version, account, container])
        token = req.environ['HTTP_X_AUTH_TOKEN']

        res = swift_connection.get(path, token)
        objects = res.body.splitlines()
        key = self.get_container_key(req)
        for obj_enc in objects:
            local_key_path = self.get_local_key_path(req)
            cipher = CompositeCipher(local_key_path)
            obj_dec = cipher.decrypt(b64decode(obj_enc), key)
            if obj == obj_dec:
                return obj_enc

        return obj_intended


class ForwardException(Exception):
    def __init__(self, method, path, reason):
        self.method = method
        self.path = path
        self.reason = reason


class EncryptedAccessException(Exception):
    def __init__(self, method, path, reason):
        self.method = method
        self.path = path
        self.reason = reason
