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
        environ = {'SERVER_NAME': self.host, 'SERVER_PORT': self.port, 'HTTP_HOST': self.host + ':' + self.port,
                   'HTTP_X_KMS_KEY_ID': key_id, 'HTTP_X_AUTH_TOKEN': token}
        req = Request.blank(path, environ=environ)

        res = get_working_response(req, self.conn_timeout, self.kms_timeout)

        key_id_return = None
        key = None
        if res:
            key_id_return = res.headers['X-Kms-Key-Id']
            key = res.body

        if len(key_id_return) != 32:
            raise ValueError('Invalid key_id')
        if len(key) != 32:
            raise ValueError('Invalid key')

        return key_id_return, key

    def head_key(self, token, key_id=None):
        environ = {'SERVER_NAME': self.host, 'SERVER_PORT': self.port,
                   'HTTP_HOST': self.host + ':' + self.port, 'METHOD': 'HEAD'}
        if key_id:
            environ['X-KMS-KEY-ID'] = key_id
        environ['X-Auth-Token'] = token
        req = Request.blank('/', environ=environ)

        res = get_working_response(req, self.conn_timeout, self.kms_timeout)
        key_id = res.environ.getattribute('X-KMS-KEY-ID', None)
        return key_id
