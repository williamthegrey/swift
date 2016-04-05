import unittest
from nose import SkipTest
from test.functional import check_response, connection
import test.functional as tf
from uuid import uuid4
from swiftclient import get_auth
from test import get_config
from swift.common.utils import config_true_value
import re


class TestEncryption(unittest.TestCase):
    def setUp(self):
        def get_urls():
            config = get_config('func_test')
            swift_test_auth_version = str(config.get('auth_version', '1'))

            swift_test_auth = 'http'
            if config_true_value(config.get('auth_ssl', 'no')):
                swift_test_auth = 'https'
            if 'auth_prefix' not in config:
                config['auth_prefix'] = '/'
            try:
                suffix = '://%(auth_host)s:%(auth_port)s%(auth_prefix)s' % config
                swift_test_auth += suffix
            except KeyError:
                pass  # skip

            if swift_test_auth_version == "1":
                swift_test_auth += 'v1.0'

            swift_url, token = \
                get_auth(swift_test_auth, config.get('username'),
                         config.get('password'),
                         snet=False,
                         tenant_name=config.get('account'),
                         auth_version=swift_test_auth_version)

            base_url = re.search('(https?://.+?)/', swift_url).group(1)
            encryption_host = config.get('encryption_host')
            encryption_port = config.get('encryption_port')
            new_base_url = 'http://' + encryption_host + ':' + encryption_port
            encryption_url = swift_url.replace(base_url, new_base_url)

            return {'swift_url': swift_url, 'encryption_url': encryption_url, 'token': token}

        urls = get_urls()
        self.swift_url = urls['swift_url']
        self.encryption_url = urls['encryption_url']
        self.token = urls['token']
        self.swift_parsed, self.swift_conn = connection(self.swift_url)
        self.encryption_parsed, self.encryption_conn = connection(self.encryption_url)
        self.container = uuid4().hex
        self.encrypted_container = uuid4().hex
        self.obj = uuid4().hex
        self.kms_container = 'kms'
        self.content = 'Nothing is true. Everything is permitted.'

    def test_composite(self):
        def put(conn, container=None, obj=None, data=None, encrypted=None):
            path = conn.parsed_url.path
            if container:
                path += '/' + container
            if obj:
                path += '/' + obj
            meta = {'X-Auth-Token': self.token}
            if encrypted and not obj:
                meta['X-Container-Meta-Encrypted'] = encrypted
            conn.request('PUT', path, data, meta)
            return check_response(conn)

        def get(conn, container=None, obj=None):
            path = conn.parsed_url.path
            if container:
                path += '/' + container
            if obj:
                path += '/' + obj
            conn.request('GET', path, None, {'X-Auth-Token': self.token})
            return check_response(conn)

        if tf.skip:
            raise SkipTest

        # test without encryption

        # using encryption_url
        res = put(self.encryption_conn, self.container)
        res.read()
        self.assertEqual(res.status, 201)

        res = get(self.encryption_conn, self.container)
        res.read()
        self.assert_(res.status in (200, 204), res.status)

        res = put(self.encryption_conn, self.container, self.obj, self.content)
        res.read()
        self.assertEqual(res.status, 201)

        res = get(self.encryption_conn, self.container, self.obj)
        content = res.read()
        self.assert_(res.status in (200, 204), res.status)
        self.assertEqual(self.content, content)

        # using swift_url
        res = get(self.swift_conn, self.container, self.obj)
        content = res.read()
        self.assert_(res.status in (200, 204), res.status)
        self.assertEqual(self.content, content)

        # test with encryption

        # using encryption_url
        res = put(self.encryption_conn, self.kms_container)
        res.read()
        self.assert_(res.status in (201, 202), res.status)

        res = get(self.encryption_conn, self.kms_container)
        res.read()
        self.assert_(res.status in (200, 204), res.status)

        res = put(self.encryption_conn, self.encrypted_container, encrypted='True')
        res.read()
        self.assertEqual(res.status, 201)

        res = get(self.encryption_conn, self.encrypted_container)
        res.read()
        self.assert_(res.status in (200, 204), res.status)
        self.assertEqual(res.getheader('x-container-meta-encrypted'), 'True')

        res = put(self.encryption_conn, self.encrypted_container, self.obj, self.content)
        res.read()
        self.assertEqual(res.status, 201)

        res = get(self.encryption_conn, self.encrypted_container, self.obj)
        content = res.read()
        self.assert_(res.status in (200, 204), res.status)
        self.assertEqual(self.content, content)

        # using swift_url
        res = get(self.swift_conn, self.encrypted_container, self.obj)
        content = res.read()
        self.assert_(res.status in (403, 404), res.status)
        self.assertNotEqual(self.content, content)

        res = get(self.swift_conn, self.encrypted_container)
        content = res.read()
        obj_enc = content.splitlines()[0]
        self.assertEqual(res.status, 200)
        self.assertNotEqual(self.obj, obj_enc)

        res = get(self.swift_conn, self.encrypted_container, obj_enc)
        content = res.read()
        self.assertEqual(res.status, 200)
        self.assertNotEqual(self.content, content)
