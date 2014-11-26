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
from swift.common.utils import public
from swift.encryption.controllers.base import Controller, delay_denial, \
    encrypted, decrypted
from swift import gettext_ as _
from swift.encryption.api import swift_api
from horizon import exceptions


class ObjectController(Controller):
    """WSGI controller for object requests."""
    server_type = 'Object'

    def __init__(self, app, account_name, container_name, object_name,
                 **kwargs):
        Controller.__init__(self, app)
        self.account_name = unquote(account_name)
        self.container_name = unquote(container_name)
        self.object_name = unquote(object_name)

    def GETorHEAD(self, req):
        """Handle HTTP GET or HEAD requests."""

        if req.method == 'GET':
            with_data = True
        else:
            with_data = False

        try:
            obj = swift_api.swift_get_object(req, self.container_name, self.object_name, \
                                             with_data=with_data)
            msg = _("Object was successfully downloaded.")
            #messages.success(request, msg)
        except Exception as e:
            exceptions.handle(req, _("Unable to download object."))

        res = Response(request=req)
        res.etag = obj.get('_apidict', None)['etag']
        res.body = obj.data

        return res

    @public
    @delay_denial
    @decrypted
    def GET(self, req):
        """Handler for HTTP GET requests."""
        return self.GETorHEAD(req)

    @public
    @delay_denial
    @decrypted
    def HEAD(self, req):
        """Handler for HTTP HEAD requests."""
        return self.GETorHEAD(req)

    @public
    @delay_denial
    @encrypted
    def POST(self, req):
        """HTTP POST request handler."""
        pass

    @public
    @delay_denial
    @encrypted
    def PUT(self, req):
        """HTTP PUT request handler."""

        try:
            obj = swift_api.swift_upload_object(req,
                                                self.container_name,
                                                self.object_name,
                                                req.body)
            msg = _("Object was successfully uploaded.")
            #messages.success(request, msg)
        except Exception as e:
            exceptions.handle(req, _("Unable to upload object."))

        res = Response(request=req)
        #res.environ['Last-Modified'] =
        res.environ['CONTENT_LENGTH'] = 0
        #res.environ['HTTP_X_TRANS_ID'] = req.environ['swift.trans_id']
        res.etag = obj.get('_apidict', None)['etag']

        return res

    @public
    @delay_denial
    def DELETE(self, req):
        """HTTP DELETE request handler."""
        pass

    @public
    @delay_denial
    def COPY(self, req):
        """HTTP COPY request handler."""
        pass
