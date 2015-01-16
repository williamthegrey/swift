__author__ = 'William'
from swift.common.bufferedhttp import http_connect_raw
from eventlet.timeout import Timeout
from swift.common.exceptions import ConnectionTimeout
from swift.common.swob import Response


def get_working_response(req, conn_timeout, res_timeout):
    source = _get_source(req, conn_timeout, res_timeout)

    res = Response(request=req)
    res.body = source.read()
    source.nuke_from_orbit()

    res.status = source.status
    update_headers(res, source.getheaders())
    if not res.environ:
        res.environ = {}
    if source.getheader('Content-Type'):
        res.charset = None
        res.content_type = source.getheader('Content-Type')

    return res


def _get_source(req, conn_timeout, res_timeout):
    server = {'ip': req.environ['SERVER_NAME'], 'port': req.environ['SERVER_PORT']}

    try:
        with ConnectionTimeout(conn_timeout):
            conn = http_connect_raw(
                server['ip'], server['port'], req.method,
                req.path, req.headers, req.query_string)

        with Timeout(res_timeout):
            conn.send(req.body)
            source = conn.getresponse()
    except Timeout as e:
        raise e

    return source


def update_headers(response, headers):
    """
    Helper function to update headers in the response.

    :param response: swob.Response object
    :param headers: dictionary headers
    """
    if hasattr(headers, 'items'):
        headers = headers.items()
    for name, value in headers:
        if name not in ('date', 'content-length', 'content-type'):
            response.headers[name] = value
