__author__ = 'William'

from swift.common.swob import Request, Response
from swift.common.http import HTTP_OK, HTTP_PARTIAL_CONTENT
from swift.common.utils import config_true_value
from eventlet.timeout import Timeout
from swift.common.exceptions import ConnectionTimeout
from swift.common.bufferedhttp import http_connect_raw
try:
    from keystoneclient.v2_0 import client as keystone_client_v2
except ImportError:
    pass

try:
    from keystoneclient.v3 import client as keystone_client_v3
except ImportError:
    pass


def keystone_api(host, port, conn_timeout=0.5, keystone_timeout=5):
    return Connection(host, port, conn_timeout, keystone_timeout)


class Connection:
    def __init__(self, host, port, conn_timeout, keystone_timeout):
        self.host = host
        self.port = port
        self.conn_timeout = conn_timeout
        self.keystone_timeout = keystone_timeout

    def get_token(self):
        pass
