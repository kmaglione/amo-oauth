"""
A class to interact with AMO's api, using OAuth.
Ripped off from Daves test_oauth.py and some notes from python-oauth2
"""
# Wherein import almost every http or urllib in Python
import urllib
import urllib2
from urlparse import urlparse, urlunparse, parse_qsl
import oauth2 as oauth
import os
import re
import time
import json
import mimetools

import requests

from utils import data_keys

# AMO Specific end points
urls = {
    'login': '/users/login',
    'request_token': '/oauth/request_token/',
    'access_token': '/oauth/access_token/',
    'authorize': '/oauth/authorize/',
    'user': '/api/2/user/',
    'addon': '/api/2/addons/',
    'checksums': '/api/2/validator-checksums',
    'versions': '/api/2/addon/%s/versions',
    'version': '/api/2/addon/%s/version/%s',
    'perf': '/api/2/performance/add',
}

storage_file = os.path.join(os.path.expanduser('~'), '.amo-oauth')
boundary = mimetools.choose_boundary()


class AMOOAuth(object):
    """
    A base class to authenticate and work with AMO OAuth.
    """
    signature_method = oauth.SignatureMethod_HMAC_SHA1()

    def __init__(self, base_url='https://addons.mozilla.org',
                 three_legged=False):
        self.data = self.read_storage()
        self.base_url = base_url.rstrip('/')
        self.three_legged = three_legged

    def set_consumer(self, consumer_key, consumer_secret):
        self.data['consumer_key'] = consumer_key
        self.data['consumer_secret'] = consumer_secret
        self.save_storage()

    def get_consumer(self):
        return oauth.Consumer(self.data['consumer_key'],
                              self.data['consumer_secret'])

    def get_access(self):
        return oauth.Token(self.data['access_token']['oauth_token'],
                           self.data['access_token']['oauth_token_secret'])

    def has_access_token(self):
        return not self.three_legged or 'access_token' in self.data

    def read_storage(self):
        if os.path.exists(storage_file):
            try:
                return json.load(open(storage_file, 'r'))
            except ValueError:
                pass
        return {}

    def url(self, key, *args):
        args = '/'.join([str(a) for a in args])
        if args:
            args = '%s' % args
        return ''.join((self.base_url, '/en-US/firefox', urls[key], args))

    def shorten(self, url):
        return urlunparse(['', ''] + list(urlparse(url)[2:]))

    def save_storage(self):
        json.dump(self.data, open(storage_file, 'w'))

    def get_csrf(self, content):
        return re.search("name='csrfmiddlewaretoken' value='(.*?)'",
                         content).groups()[0]

    def _request(self, token, method, url, data={}, headers={}, files={},
                 **kw):
        parameters = data_keys(data)
        parameters.update(kw)

        request = oauth.Request.from_consumer_and_token(
            self.get_consumer(), token, method, url, parameters)
        request.sign_request(self.signature_method, self.get_consumer(), token)

        headers = headers.copy()
        params = {}

        if method == 'GET':
            assert not (data or kw or files)
            url = request.to_url()

        elif method == 'POST':
            if files:
                headers.update(request.to_header())
                params.update({'files': files,
                               'params': parameters})
            elif False:
                headers.update(request.to_header())
                params['data'] = parameters
            else:
                headers['Content-Type'] = 'application/x-www-form-urlencoded'
                params['data'] = request.to_postdata()

        else:
            raise ValueError()

        return requests.request(method, url, headers=headers,
                                allow_redirects=False, **params)

    def authenticate(self, username=None, password=None):
        """
        This is only for the more convoluted three legged approach.
        1. Login into AMO.
        2. Get a request token for the consumer.
        3. Approve the consumer.
        4. Get an access token.
        """
        # First we need to login to AMO, this takes a few steps.
        # If this was being done in a browser, this wouldn't matter.
        #
        # This callback is pretty academic, but required so we can get
        # verification token.
        callback = 'http://foo.com/'

        opener = urllib2.build_opener(urllib2.HTTPCookieProcessor())
        urllib2.install_opener(opener)
        res = opener.open(self.url('login'))
        assert res.code == 200

        # get the CSRF middleware token
        if password is None:
            from getpass import getpass
            password = getpass()

        csrf = self.get_csrf(res.read())
        data = urllib.urlencode({'username': username,
                                 'password': password,
                                 'csrfmiddlewaretoken': csrf})
        res = opener.open(self.url('login'), data)
        assert res.code == 200

        # We need these headers to be able to post to the authorize method
        cookies = {}
        # Need to find a better way to find the handler, -2 is fragile.
        for cookie in opener.handlers[-2].cookiejar:
            if cookie.name == 'sessionid':
                cookies = {'Cookie': '%s=%s' % (cookie.name, cookie.value)}
        # Step 1 completed, we can now be logged in for any future requests

        # Step 2, get a request token.
        resp = self._request(None, 'GET', self.url('request_token'),
                             oauth_callback=callback)
        assert resp.status_code == 200, 'Status was: %s' % resp.status_code

        request_token = dict(parse_qsl(resp.content))
        assert request_token
        token = oauth.Token(request_token['oauth_token'],
                            request_token['oauth_token_secret'])

        # Step 3, authorize the access of this consumer for this user account.
        resp = self._request(token, 'GET', self.url('authorize'),
                             headers=cookies)
        csrf = self.get_csrf(resp.content)
        data = {'authorize_access': True,
                'csrfmiddlewaretoken': csrf,
                'oauth_token': token.key}
        resp = self._request(token, 'POST', self.url('authorize'),
                             headers=cookies, data=data,
                             oauth_callback=callback)
        assert resp.status_code == 302, 'Status was: %s' % resp.status_code

        qsl = parse_qsl(resp.headers['location'][len(callback) + 1:])
        verifier = dict(qsl)['oauth_verifier']
        token.set_verifier(verifier)

        # We have now authorized the app for this user.
        resp = self._request(token, 'GET', self.url('access_token'))
        access_token = dict(parse_qsl(resp.content))
        self.data['access_token'] = access_token
        self.save_storage()
        # Done. Wasn't that fun?

    def get_params(self):
        return dict(oauth_consumer_key=self.data['consumer_key'],
                    oauth_nonce=oauth.generate_nonce(),
                    oauth_signature_method='HMAC-SHA1',
                    oauth_timestamp=int(time.time()),
                    oauth_version='1.0')

    def _send(self, url, method, data={}, files={}):
        token = (self.get_access()
                 if self.three_legged and self.has_access_token()
                 else None)

        resp = self._request(token, method, url, data=data, files=files)
        if resp.status_code not in [200, 201]:
            resp.raise_for_status()

        try:
            return resp.json()
        except ValueError:
            return resp.content

    def get_user(self):
        return self._send(self.url('user'), 'GET')

    def create_addon(self, data):
        return self._send(self.url('addon'), 'POST', data)

    def create_version(self, data, id):
        return self._send(self.url('versions') % id, 'POST', data)

    def get_versions(self, addon_id):
        return self._send(self.url('versions') % addon_id, 'GET')

    def get_version(self, addon_id, version_id):
        return self._send(self.url('version') % (addon_id, version_id),
                          'GET', {})

    def get_checksums(self):
        return self._send(self.url('checksums'), 'GET')

    def set_checksums(self, data):
        return self._send(self.url('checksums'), 'POST',
                          {'checksum_json': data})

    def perf(self, data):
        return self._send(self.url('perf'), 'POST', data)
