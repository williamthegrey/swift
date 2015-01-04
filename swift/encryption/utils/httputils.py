__author__ = 'William'
from swift.common.bufferedhttp import http_connect_raw
from eventlet.timeout import Timeout
from swift.common.exceptions import ConnectionTimeout
from swift.common.swob import Request, Response
import logging
from swift.common.http import HTTP_OK, HTTP_PARTIAL_CONTENT


def get_working_response(req, conn_timeout, res_timeout):
    source = _get_source(req, conn_timeout, res_timeout)
    res = None
    if source:
        res = Response(request=req)
        res.body = source.read()
        source.nuke_from_orbit()

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

        res.status = source.status
        if not res.environ:
            res.environ = {}

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
            possible_source = conn.getresponse()
    except (Exception, Timeout) as e:
        logging.exception('Trying to %(method)s %(path)s' % {'method': req.method, 'path': req.path})
        possible_source = None

    # TODO: best response
    source = possible_source

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
        if name == 'etag':
            response.headers[name] = value.replace('"', '')
        elif name not in ('date', 'content-length', 'content-type',
                          'connection', 'x-put-timestamp', 'x-delete-after'):
            response.headers[name] = value
