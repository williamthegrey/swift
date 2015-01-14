__author__ = 'William'

from swift.common.swob import Request, Response
from swift.encryption.utils.httputils import get_working_response


def swift_api(host, port, conn_timeout=0.5, proxy_timeout=5):
    return Connection(host, port, conn_timeout, proxy_timeout)


class Connection:
    def __init__(self, host, port, conn_timeout, proxy_timeout):
        self.host = host
        self.port = port
        self.conn_timeout = conn_timeout
        self.proxy_timeout = proxy_timeout

    def head_container_meta_encrypted(self, path, token):
        environ = {'SERVER_NAME': self.host, 'SERVER_PORT': self.port,
                   'HTTP_HOST': self.host + ':' + self.port, 'HTTP_X_AUTH_TOKEN': token,
                   'REQUEST_METHOD': 'HEAD'}
        req = Request.blank(path, environ=environ)

        res = get_working_response(req, self.conn_timeout, self.proxy_timeout)

        encrypted = 'False'
        if res:
            encrypted = res.headers['X-Container-Meta-Encrypted']
            if encrypted not in ('True', 'true'):
                encrypted = 'False'

        return encrypted
