__author__ = 'William'

from eventlet import Timeout
from time import time
from swift import gettext_ as _
from swift.common.swob import HTTPBadRequest, HTTPForbidden, \
    HTTPMethodNotAllowed, HTTPNotFound, HTTPPreconditionFailed, \
    HTTPServerError, HTTPException, Request
from swift.common.utils import get_logger, get_remote_client, split_path, generate_trans_id
from swift.common.constraints import check_utf8
from swift.encryption.controllers import AccountController, ContainerController, ObjectController
from swift.encryption.controllers.base import ForwardException


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

        self.proxy_timeout = int(conf.get('proxy_timeout', 10))
        self.recoverable_proxy_timeout = int(
            conf.get('recoverable_proxy_timeout', self.proxy_timeout))
        self.kms_timeout = int(conf.get('kms_timeout', 5))
        self.auth_timout = int(conf.get('auth_timeout', 5))
        self.conn_timeout = float(conf.get('conn_timeout', 0.5))
        self.client_timeout = int(conf.get('client_timeout', 60))

        self.deny_host_headers = [
            host.strip() for host in
            conf.get('deny_host_headers', '').split(',') if host.strip()]
        self.trans_id_suffix = conf.get('trans_id_suffix', '')

        try:
            self.proxy_host = conf.get('proxy_host', None)
        except KeyError:
            self.logger.exception('Cannot get proxy_host from %s' % conf.get('__file__', None))

        try:
            self.proxy_port = conf.get('proxy_port', None)
        except KeyError:
            self.logger.exception('Cannot get proxy_port from %s' % conf.get('__file__', None))

        try:
            self.kms_host = conf.get('kms_host', None)
        except KeyError:
            self.logger.exception('Cannot get kms_host from %s' % conf.get('__file__', None))

        try:
            self.kms_port = conf.get('kms_port', None)
        except KeyError:
            self.logger.exception('Cannot get kms_port from %s' % conf.get('__file__', None))

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
        except (Exception, Timeout):
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

            return handler(req)
        except HTTPException as error_response:
            return error_response
        except ForwardException as e:
            self.logger.exception(_('ERROR Failed to forward to swift proxy due to %s' % e.reason))
            return HTTPServerError(request=req)
        except (Exception, Timeout) as e:
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

        if obj and container and account:
            return ObjectController, d
        elif container and account:
            return ContainerController, d
        elif account and not container and not obj:
            return AccountController, d
        return None, d

    def error_occurred(self, proxy, msg):
        """
        Handle logging, and handling of errors.

        :param proxy: dictionary of proxy to handle errors for
        :param msg: error message
        """
        proxy['errors'] = proxy.get('errors', 0) + 1
        proxy['last_error'] = time()
        self.logger.error(_('%(msg)s %(ip)s:%(port)s'),
                          {'msg': msg, 'ip': proxy['ip'],
                          'port': proxy['port']})

    def exception_occurred(self, proxy, typ, additional_info):
        """
        Handle logging of generic exceptions.

        :param proxy: dictionary of proxy to log the error for
        :param typ: server type
        :param additional_info: additional information to log
        """
        self.logger.exception(
            _('ERROR with %(type)s server %(ip)s:%(port)s re: '
              '%(info)s'),
            {'type': typ, 'ip': proxy['ip'], 'port': proxy['port'],
             'info': additional_info})


def app_factory(global_conf, **local_conf):
    """paste.deploy app factory for creating WSGI encryption server apps."""
    conf = global_conf.copy()
    conf.update(local_conf)
    app = Application(conf)
    app.check_config()
    return app
