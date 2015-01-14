__author__ = 'William'

from swift.common.swob import Request, Response
from swift.encryption.utils.httputils import get_working_response


def kms_api(host, port, conn_timeout=0.5, kms_timeout=5):
    return Connection(host, port, conn_timeout, kms_timeout)


class Connection:
    def __init__(self, host, port, conn_timeout, kms_timeout):
        self.host = host
        self.port = port
        self.conn_timeout = conn_timeout
        self.kms_timeout = kms_timeout

    def get_key(self, path, token, key_id=None):
        environ = {'SERVER_NAME': self.host, 'SERVER_PORT': self.port,
                   'HTTP_HOST': self.host + ':' + self.port, 'HTTP_X_AUTH_TOKEN': token,
                   'HTTP_X_KMS_KEY_ID': key_id}
        req = Request.blank(path, environ=environ)

        res = get_working_response(req, self.conn_timeout, self.kms_timeout)

        key_id_return = None
        key = None
        if res:
            key_id_return = res.headers['X-Kms-Key-Id']
            key = res.body

        if not key_id_return or len(key_id_return) != 32:
            raise ValueError('Invalid key_id')
        if not key or len(key) != 32:
            raise ValueError('Invalid key')

        return key_id_return, key

    def head_key(self, path, token, key_id=None):
        environ = {'SERVER_NAME': self.host, 'SERVER_PORT': self.port,
                   'HTTP_HOST': self.host + ':' + self.port, 'HTTP_X_AUTH_TOKEN': token,
                   'HTTP_X_KMS_KEY_ID': key_id, 'REQUEST_METHOD': 'HEAD'}
        req = Request.blank(path, environ=environ)

        res = get_working_response(req, self.conn_timeout, self.kms_timeout)
        key_id_return = None
        if res:
            key_id_return = res.headers['X-Kms-Key-Id']

        if not key_id_return or len(key_id_return) != 32:
            raise ValueError('Invalid key_id')

        return key_id
