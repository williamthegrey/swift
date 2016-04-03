from swift.common.http import is_success
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

    def get_key(self, path, token, not_null=False):
        environ = {'SERVER_NAME': self.host, 'SERVER_PORT': self.port,
                   'HTTP_HOST': self.host + ':' + self.port, 'HTTP_X_AUTH_TOKEN': token}
        req = Request.blank(path, environ=environ)

        res = get_working_response(req, self.conn_timeout, self.kms_timeout)

        key = None
        if res and is_success(res.status_int):
            key = res.body

        if not_null and not key:
                raise KmsException('No key was found')

        return key

    def head_key(self, path, token, not_null=False):
        environ = {'SERVER_NAME': self.host, 'SERVER_PORT': self.port,
                   'HTTP_HOST': self.host + ':' + self.port, 'HTTP_X_AUTH_TOKEN': token,
                   'REQUEST_METHOD': 'HEAD'}
        req = Request.blank(path, environ=environ)

        res = get_working_response(req, self.conn_timeout, self.kms_timeout)

        headers = None
        if res and is_success(res.status_int):
            headers = res.headers

        if not_null:
            if not headers:
                raise KmsException('No key was found')

        return headers

    def put_key(self, path, key, token):
        environ = {'SERVER_NAME': self.host, 'SERVER_PORT': self.port,
                   'HTTP_HOST': self.host + ':' + self.port, 'HTTP_X_AUTH_TOKEN': token,
                   'REQUEST_METHOD': 'PUT'}
        req = Request.blank(path, environ=environ)
        req.body = key

        res = get_working_response(req, self.conn_timeout, self.kms_timeout)

        if not res or not is_success(res.status_int):
            raise KmsException('Put key failed')

        return res

    def post_key(self, path, headers, token):
        pass

    def delete_key(self, path, token):
        pass


class KmsException(Exception):
    def __init__(self, reason):
        self.reason = reason
