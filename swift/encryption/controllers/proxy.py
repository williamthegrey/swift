# Copyright (c) 2010-2012 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# NOTE: swift_conn
# You'll see swift_conn passed around a few places in this file. This is the
# source bufferedhttp connection of whatever it is attached to.
#   It is used when early termination of reading from the connection should
# happen, such as when a range request is satisfied but there's still more the
# source connection would like to send. To prevent having to read all the data
# that could be left, the source connection can be .close() and then reads
# commence to empty out any buffers.
#   These shenanigans are to ensure all related objects can be garbage
# collected. We've seen objects hang around forever otherwise.

from urllib import unquote, quote
from swift.common.swob import Response
from swift.common.utils import public, config_true_value
from swift.encryption.controllers.base import Controller, delay_denial, \
    encrypted, decrypted
from swift import gettext_ as _
from swift.encryption.api import swift_api
from swift.common.bufferedhttp import http_connect_raw
from eventlet.timeout import Timeout
from swift.common.http import HTTP_OK, HTTP_PARTIAL_CONTENT
from swift.encryption.controllers.base import update_headers
import functools


def redirected(func):
    """
    Decorator to redirect a request and its response for a controller method

    :param func: a controller method to redirect requests and responses for
    """

    @functools.wraps(func)
    def wrapped(*a, **kw):
        req = a[1]
        remote_addr = req.environ['REMOTE_ADDR']
        remote_port = req.environ['REMOTE_PORT']
        http_host = req.environ['HTTP_HOST']
        server_name = req.environ['SERVER_NAME']
        server_port = req.environ['SERVER_PORT']

        proxy_host = req.environ['proxy_host']
        del req.environ['proxy_host']
        proxy_port = req.environ['proxy_port']
        del req.environ['proxy_port']

        # change remote
        req.environ['REMOTE_ADDR'] = server_name
        #req.environ['REMOTE_PORT'] = None

        # change server
        req.environ['HTTP_HOST'] = proxy_host + ":" + proxy_port
        req.environ['SERVER_NAME'] = proxy_host
        req.environ['SERVER_PORT'] = proxy_port

        # call controller
        res = func(*a, **kw)

        # reset remote
        res.environ['REMOTE_ADDR'] = remote_addr
        #req.environ['REMOTE_PORT'] = remote_port

        # reset server
        req.environ['HTTP_HOST'] = http_host
        req.environ['SERVER_NAME'] = server_name
        req.environ['SERVER_PORT'] = server_port

        return res
    return wrapped


class ProxyController(Controller):
    """WSGI controller for object requests."""
    server_type = 'Proxy'

    def __init__(self, app, account_name, container_name, object_name,
                 **kwargs):
        Controller.__init__(self, app)
        self.account_name = unquote(account_name)
        self.container_name = unquote(container_name)
        self.object_name = unquote(object_name)

    def GETorHEAD(self, req):
        """Handle HTTP GET or HEAD requests."""

        res = self.get_working_response(req)
        return res

    @public
    @delay_denial
    @redirected
    @decrypted
    def GET(self, req):
        """Handler for HTTP GET requests."""

        return self.GETorHEAD(req)

    @public
    @delay_denial
    @redirected
    def HEAD(self, req):
        """Handler for HTTP HEAD requests."""

        return self.GETorHEAD(req)

    @public
    @delay_denial
    @redirected
    @encrypted
    def PUT(self, req):
        """HTTP PUT request handler."""

        res = self.get_working_response(req)
        return res

    @public
    @delay_denial
    @redirected
    def POST(self, req):
        """HTTP POST request handler."""

        res = self.get_working_response(req)
        return res

    @public
    @delay_denial
    @redirected
    def DELETE(self, req):
        """HTTP DELETE request handler."""

        res = self.get_working_response(req)
        return res

    @public
    @delay_denial
    @redirected
    def COPY(self, req):
        """HTTP COPY request handler."""

        res = self.get_working_response(req)
        return res

    def get_working_response(self, req):
        source, proxy = self._get_source_and_proxy(req)
        res = None
        if source:
            res = Response(request=req)
            res.body = source.read()
            source.nuke_from_orbit()

            if req.method == 'GET' and \
                    source.status in (HTTP_OK, HTTP_PARTIAL_CONTENT):
                # See NOTE: swift_conn at top of file about this.
                res.swift_conn = source.swift_conn
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

        return res

    def _get_source_and_proxy(self, req):
        proxy_timeout = self.app.proxy_timeout
        newest = config_true_value(req.headers.get('x-newest', 'f'))
        if self.server_type == 'Object' and not newest:
            proxy_timeout = self.app.recoverable_proxy_timeout

        proxy = {'ip': '192.168.1.19', 'port': '8080'}

        try:
        #with ConnectionTimeout(self.app.conn_timeout):
            conn = http_connect_raw(
                proxy['ip'], proxy['port'], req.method,
                req.path, req.headers, req.query_string)

        #with Timeout(proxy_timeout):
            conn.send(req.body)
            possible_source = conn.getresponse()
            # See NOTE: swift_conn at top of file about this.
            possible_source.swift_conn = conn
        except (Exception, Timeout) as e:
            self.app.exception_occurred(
                proxy, self.server_type,
                _('Trying to %(method)s %(path)s') %
                {'method': req.method, 'path': req.path})

        source = possible_source

        return source, proxy
