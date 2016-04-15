import inspect
from urllib import unquote
from swift.encryption.utils.encryptionutils import AESCipher, RSACipher, EncryptionException
from swift.common.utils import split_path
from swift.encryption.utils.httputils import get_working_response
import functools
from base64 import urlsafe_b64encode as b64encode
from base64 import urlsafe_b64decode as b64decode
from swift.encryption.api.kms_api import kms_api
from swift.encryption.api.swift_api import swift_api
from eventlet.timeout import Timeout
from Crypto.PublicKey import RSA
from swift.common.swob import Response


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
        remote_addr = None
        if 'REMOTE_ADDR' in req.environ:
            remote_addr = req.environ['REMOTE_ADDR']
        remote_port = None
        if 'REMOTE_PORT' in req.environ:
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
        if 'REMOTE_ADDR' in req.environ:
            req.environ['REMOTE_ADDR'] = remote_addr
        if 'REMOTE_PORT' in req.environ:
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
            cipher = controller.get_cipher(req)
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
        self.cipher = None

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

    def get_cipher(self, req):
        if not self.cipher:
            self.cipher = ControllerCompositeCipher(self, req)

        return self.cipher

    def get_kms_api(self):
        kms_host = self.app.kms_host
        kms_port = self.app.kms_port
        kms_timeout = self.app.kms_timeout
        conn_timeout = self.app.conn_timeout

        return kms_api(kms_host, kms_port, conn_timeout, kms_timeout)

    def build_key_path(self, req, key_type, ext_user_id=None):
        if ext_user_id:
            user_id = ext_user_id
        else:
            user_id = req.environ['HTTP_X_USER_ID']

        if key_type != 'user' and key_type != 'container' and key_type != 'object':
            return None

        path = unquote(req.path)

        if key_type == 'user':
            segment = 2
        elif key_type == 'container':
            segment = 3
        elif key_type == 'object':
            segment = 4
        else:
            return None

        version, account, container, obj = split_path(path, segment, 4, True)
        fragment = [version, account]
        if self.app.kms_prefix and self.app.kms_prefix != '':
            fragment += [self.app.kms_prefix]
            segment += 1
        fragment += [user_id, container, obj]
        segment += 1

        return '/' + '/'.join(fragment[0:segment])

    def get_key(self, req, key_type, ext_user_id=None, not_null=False):
        kms_connection = self.get_kms_api()
        key_path = self.build_key_path(req, key_type, ext_user_id)
        token = req.environ['HTTP_X_AUTH_TOKEN']
        return kms_connection.get_key(key_path, token, not_null)

    def get_user_key(self, req, ext_user_id=None, not_null=False):
        return self.get_key(req, 'user', ext_user_id, not_null)

    def get_container_key(self, req, ext_user_id=None, not_null=False):
        return self.get_key(req, 'container', ext_user_id, not_null)

    def get_object_key(self, req, ext_user_id=None, not_null=False):
        return self.get_key(req, 'object', ext_user_id, not_null)

    def put_key(self, req, key_type, key, ext_user_id=None):
        kms_connection = self.get_kms_api()
        key_path = self.build_key_path(req, key_type, ext_user_id)
        token = req.environ['HTTP_X_AUTH_TOKEN']
        return kms_connection.put_key(key_path, key, token)

    def put_user_key(self, req, key, ext_user_id=None):
        return self.put_key(req, 'user', key, ext_user_id)

    def put_container_key(self, req, key, ext_user_id=None):
        return self.put_key(req, 'container', key, ext_user_id)

    def put_object_key(self, req, key, ext_user_id=None):
        return self.put_key(req, 'object', key, ext_user_id)

    def head_key(self, req, key_type, ext_user_id=None, not_null=False):
        kms_connection = self.get_kms_api()
        key_path = self.build_key_path(req, key_type, ext_user_id)
        token = req.environ['HTTP_X_AUTH_TOKEN']
        return kms_connection.head_key(key_path, token, not_null)

    def head_user_key(self, req, ext_user_id=None, not_null=False):
        return self.head_key(req, 'user', ext_user_id, not_null)

    def head_container_key(self, req, ext_user_id=None, not_null=False):
        return self.head_key(req, 'container', ext_user_id, not_null)

    def head_object_key(self, req, ext_user_id=None, not_null=False):
        return self.head_key(req, 'object', ext_user_id, not_null)

    def post_key(self, req, key_type, headers, ext_user_id=None):
        kms_connection = self.get_kms_api()
        key_path = self.build_key_path(req, key_type, ext_user_id)
        token = req.environ['HTTP_X_AUTH_TOKEN']
        return kms_connection.post_key(key_path, headers, token)

    def post_user_key(self, req, headers, ext_user_id=None):
        return self.post_key(req, 'user', headers, ext_user_id)

    def post_container_key(self, req, headers, ext_user_id=None):
        return self.post_key(req, 'container', headers, ext_user_id)

    def post_object_key(self, req, headers, ext_user_id=None):
        return self.post_key(req, 'object', headers, ext_user_id)

    def delete_key(self, req, key_type, ext_user_id=None):
        kms_connection = self.get_kms_api()
        key_path = self.build_key_path(req, key_type, ext_user_id)
        token = req.environ['HTTP_X_AUTH_TOKEN']
        return kms_connection.delete_key(key_path, token)

    def delete_user_key(self, req, ext_user_id=None):
        return self.delete_key(req, 'user', ext_user_id)

    def delete_container_key(self, req, ext_user_id=None):
        return self.delete_key(req, 'container', ext_user_id)

    def delete_object_key(self, req, ext_user_id=None):
        return self.delete_key(req, 'object', ext_user_id)

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
            cipher = self.get_cipher(req)
            obj_dec = cipher.decrypt(b64decode(obj_enc), key)
            if obj == obj_dec:
                return obj_enc

        return obj_intended

    def share(self, req, share_type):
        ext_user_id = req.environ['HTTP_X_SHARED_USER_ID']
        ext_pub_key = self.get_user_key(req, ext_user_id, not_null=True)
        if share_type == 'container':
            key = self.get_container_key(req)
        elif share_type == 'object':
            key = self.get_object_key(req)
        else:
            raise ValueError('Invalid sharing type')

        cipher = self.get_cipher(req)
        key_re_enc = cipher.rsa_cipher.re_encrypt(key, RSA.importKey(ext_pub_key))

        if share_type == 'container':
            self.put_container_key(req, key_re_enc[0], ext_user_id)
        elif share_type == 'object':
            self.put_object_key(req, key_re_enc[0], ext_user_id)
        else:
            raise ValueError('Invalid sharing type')

        res = Response(request=req)
        res.body = '<html><h1>Accepted</h1><p>The request is accepted for processing.</p></html>'
        res.status = '202 Accepted'

        return res


class ControllerCompositeCipher(object):
    def __init__(self, controller, req):
        self.rsa_cipher = ControllerRSACipher(controller, req)
        self.aes_cipher = AESCipher()

    def generate_key(self):
        return self.rsa_cipher.encrypt(self.aes_cipher.key)

    def encrypt(self, msg, key):
        self.aes_cipher.key = self.rsa_cipher.decrypt(key)

        return self.aes_cipher.encrypt(msg)

    def decrypt(self, msg, key):
        self.aes_cipher.key = self.rsa_cipher.decrypt(key)

        return self.aes_cipher.decrypt(msg)

    def encrypt_sign(self, msg, key=None):
        if key:
            self.aes_cipher.key = key

        key = self.rsa_cipher.encrypt(self.aes_cipher.key)
        msg_enc = self.aes_cipher.encrypt(msg)
        signature = self.rsa_cipher.sign(msg_enc)

        return {'msg': msg_enc, 'signature': signature, 'key': key}

    def verify_decrypt(self, msg, signature, key, ext_pub_key=None):
        if self.rsa_cipher.verify(msg, signature, ext_pub_key):
            self.aes_cipher.key = self.rsa_cipher.decrypt(key)
            return self.aes_cipher.decrypt(msg)
        else:
            raise EncryptionException('The message is corrupted.')


class ControllerRSACipher(RSACipher):

    def __init__(self, controller, req):
        self.controller = controller
        self.req = req
        self.local_key_path = self.get_local_key_path(req)
        RSACipher.__init__(self, self.local_key_path)

    def get_local_key_path(self, req):
        user_id = req.environ['HTTP_X_USER_ID']
        local_key_path = self.controller.app.local_key_dir + user_id + '.pem'
        return local_key_path

    def register_key(self, pub_key):
        self.controller.put_user_key(self.req, pub_key.exportKey('PEM'))

    def check_key(self, pub_key):
        key = self.controller.get_user_key(self.req)
        if not key or key != pub_key.exportKey('PEM'):
            self.register_key(pub_key)


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
