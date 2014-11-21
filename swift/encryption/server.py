__author__ = 'William'

from eventlet import Timeout
from swift import gettext_ as _
from swift.common.swob import HTTPBadRequest, HTTPForbidden, \
    HTTPMethodNotAllowed, HTTPNotFound, HTTPPreconditionFailed, \
    HTTPServerError, HTTPException, Request
from swift.common.utils import get_logger, get_remote_client, split_path, generate_trans_id
from swift.common.constraints import check_utf8
from swift.encryption.controllers import Controller


class Application(object):
    """WSGI application for the encryption server."""

    def __init__(self, conf, logger=None):
        if conf is None:
            conf = {}
        if logger is None:
            self.logger = get_logger(conf, log_route='encryption-server')
        else:
            self.logger = logger

        swift_dir = conf.get('swift_dir', '/etc/swift')
        self.swift_dir = swift_dir

        self.deny_host_headers = [
            host.strip() for host in
            conf.get('deny_host_headers', '').split(',') if host.strip()]
        self.trans_id_suffix = conf.get('trans_id_suffix', '')

        try:
            self.swift_url = conf.get('swift_url', None)
        except KeyError:
            self.logger.exception('Cannot get swift_url from %s' % conf.get('__file__', None))

        try:
            self.km_url = conf.get('km_url', None)
        except KeyError:
            self.logger.exception('Cannot get km_url from %s' % conf.get('__file__', None))

        self.openstack_ssl_cacert = conf.get('openstack_ssl_cacert', None)
        self.api_result_limit = conf.get('api_result_limit', None)

    def check_config(self):
        """
        Check the configuration for possible errors
        """
        pass

    def __call__(self, env, start_response):
        """
        WSGI entry point.
        Wraps env in swob.Request object and passes it down.

        :param env: WSGI environment dictionary
        :param start_response: WSGI callable
        """
        try:
            req = Request(env)
            return self.handle_request(req)(env, start_response)
        except UnicodeError:
            err = HTTPPreconditionFailed(
                request=req, body='Invalid UTF8 or contains NULL')
            return err(env, start_response)
        except (Exception, Timeout) as e:
            start_response('500 Server Error',
                           [('Content-Type', 'text/plain')])
            return ['Internal server error.\n']

    def handle_request(self, req):
        """
        Entry point for encryption server.
        Should return a WSGI-style callable (such as swob.Response).

        :param req: swob.Request object
        """
        try:
            self.logger.set_statsd_prefix('encryption-server')
            if req.content_length and req.content_length < 0:
                self.logger.increment('errors')
                return HTTPBadRequest(request=req,
                                      body='Invalid Content-Length')

            try:
                if not check_utf8(req.path_info):
                    self.logger.increment('errors')
                    return HTTPPreconditionFailed(
                        request=req, body='Invalid UTF8 or contains NULL')
            except UnicodeError:
                self.logger.increment('errors')
                return HTTPPreconditionFailed(
                    request=req, body='Invalid UTF8 or contains NULL')

            try:
                controller, path_parts = self.get_controller(req.path)
                p = req.path_info
                if isinstance(p, unicode):
                    p = p.encode('utf-8')
            except ValueError:
                self.logger.increment('errors')
                return HTTPNotFound(request=req)
            if not controller:
                self.logger.increment('errors')
                return HTTPPreconditionFailed(request=req, body='Bad URL')
            if self.deny_host_headers and \
                    req.host.split(':')[0] in self.deny_host_headers:
                return HTTPForbidden(request=req, body='Invalid host header')

            self.logger.set_statsd_prefix('encryption-server.' +
                                          controller.server_type.lower())
            controller = controller(self, **path_parts)
            if 'swift.trans_id' not in req.environ:
                # if this wasn't set by an earlier middleware, set it now
                trans_id_suffix = self.trans_id_suffix
                trans_id_extra = req.headers.get('x-trans-id-extra')
                if trans_id_extra:
                    trans_id_suffix += '-' + trans_id_extra[:32]
                trans_id = generate_trans_id(trans_id_suffix)
                req.environ['swift.trans_id'] = trans_id
                self.logger.txn_id = trans_id
            req.headers['x-trans-id'] = req.environ['swift.trans_id']
            controller.trans_id = req.environ['swift.trans_id']
            self.logger.client_ip = get_remote_client(req)
            try:
                handler = getattr(controller, req.method)
                getattr(handler, 'publicly_accessible')
            except AttributeError:
                allowed_methods = getattr(controller, 'allowed_methods', set())
                return HTTPMethodNotAllowed(
                    request=req, headers={'Allow': ', '.join(allowed_methods)})
            if 'swift.authorize' in req.environ:
                # We call authorize before the handler, always. If authorized,
                # we remove the swift.authorize hook so isn't ever called
                # again. If not authorized, we return the denial unless the
                # controller's method indicates it'd like to gather more
                # information and try again later.
                resp = req.environ['swift.authorize'](req)
                if not resp:
                    # No resp means authorized, no delayed recheck required.
                    del req.environ['swift.authorize']
                else:
                    # Response indicates denial, but we might delay the denial
                    # and recheck later. If not delayed, return the error now.
                    if not getattr(handler, 'delay_denial', None):
                        return resp
            # Save off original request method (GET, POST, etc.) in case it
            # gets mutated during handling.  This way logging can display the
            # method the client actually sent.
            req.environ['swift.orig_req_method'] = req.method

            req.environ['swift_url'] = self.swift_url + '/' + path_parts['version'] + '/' + path_parts['account_name']
            req.environ['km_url'] = self.km_url
            req.environ['openstack_ssl_cacert'] = self.openstack_ssl_cacert
            req.environ['api_result_limit'] = self.api_result_limit

            return handler(req)
        except HTTPException as error_response:
            return error_response
        except (Exception, Timeout):
            self.logger.exception(_('ERROR Unhandled exception in request'))
            return HTTPServerError(request=req)

    def get_controller(self, path):
        """
        Get the controller to handle a request.

        :param path: path from request
        :returns: tuple of (controller class, path dictionary)

        :raises: ValueError (thrown by split_path) if given invalid path
        """
        version, account, container, obj = split_path(path, 1, 4, True)
        d = dict(version=version,
                 account_name=account,
                 container_name=container,
                 object_name=obj)
        return Controller, d


def app_factory(global_conf, **local_conf):
    """paste.deploy app factory for creating WSGI encryption server apps."""
    conf = global_conf.copy()
    conf.update(local_conf)
    app = Application(conf)
    app.check_config()
    return app
