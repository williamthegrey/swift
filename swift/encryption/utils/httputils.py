__author__ = 'William'
from swift.common.bufferedhttp import http_connect_raw
from eventlet.timeout import Timeout
from swift.common.exceptions import ConnectionTimeout
from swift.common.swob import Request, Response
import logging


def get_working_response(req, conn_timeout, res_timeout):
    source = _get_source(req, conn_timeout, res_timeout)
    res = None
    if source:
        res = Response(request=req)
        res.body = source.read()
        source.nuke_from_orbit()
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
