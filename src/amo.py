"""
A class to interact with AMO's api, using OAuth.
Ripped off from Daves test_oauth.py and some notes from python-oauth2
"""
# Wherein import almost every http or urllib in Python
import urllib
import urllib2
from urlparse import urlparse, urlunparse, parse_qsl
import httplib
import oauth2 as oauth
import os
import re
import time
import json
import mimetools

from utils import encode_multipart

# AMO Specific end points
urls = {
    'login': '/users/login',
    'request_token': '/oauth/request_token/',
    'access_token': '/oauth/access_token/',
    'authorize': '/oauth/authorize/',
    'user': '/api/2/user/',
    'addon': '/api/2/addons/',
}

storage_file = os.path.join(os.path.expanduser('~'), '.amo-oauth')
boundary = mimetools.choose_boundary()


class AMOOAuth:
    """
    A base class to authenticate and work with AMO OAuth.
    """

    def __init__(self, domain="addons.mozilla.org", protocol='https',
                 port=443):
        self.data = self.read_storage()
        self.domain = domain
        self.protocol = protocol
        self.port = port

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
        return 'access_token' in self.data

    def read_storage(self):
        if os.path.exists(storage_file):
            try:
                return json.load(open(storage_file, 'r'))
            except ValueError:
                pass
        return {}

    def url(self, key):
        return urlunparse((self.protocol, '%s:%s' % (self.domain, self.port),
                           '/en-US/firefox%s' % urls[key], '', '', ''))

    def shorten(self, url):
        return urlunparse(['', ''] + list(urlparse(url)[2:]))

    def save_storage(self):
        json.dump(self.data, open(storage_file, 'w'))

    def get_csrf(self, content):
        return re.search("name='csrfmiddlewaretoken' value='(.*?)'",
                         content).groups()[0]

    def authenticate(self, username=None, password=None):
        """
        1. Login into AMO.
        2. Get a request token for the consumer.
        3. Approve the consumer.
        4. Get an access token.
        """
        # First we need to login to AMO, this takes a few steps.
        # If this was being done in a browser, this wouldn't matter.
        opener = urllib2.build_opener(urllib2.HTTPCookieProcessor())
        urllib2.install_opener(opener)
        res = opener.open(self.url('login'))

        # get the CSRF middleware token
        if password is None:
            password = raw_input('Enter password: ')

        csrf = self.get_csrf(res.read())
        data = urllib.urlencode({'username': username,
                                 'password': password,
                                 'csrfmiddlewaretoken': csrf})
        res = opener.open(self.url('login'), data)

        # We need these headers to be able to post to the authorize method
        cookies = []
        for cookie in opener.handlers[-2].cookiejar:
            cookies.append("%s=%s" % (cookie.name, cookie.value))
        headers = {'Cookie': ', '.join(cookies)}
        # Step 1 completed, we can now be logged in for any future requests

        # Step 2, get a request token.
        client = oauth.Client(self.get_consumer())
        resp, content = client.request(self.url('request_token'), "GET")
        assert resp.status == 200, 'Status was: %s' % resp.status

        request_token = dict(parse_qsl(content))
        token = oauth.Token(request_token['oauth_token'],
                            request_token['oauth_token_secret'])

        # Step 3, authorize the access of this consumer for this user account.
        client = oauth.Client(self.get_consumer(), token)
        resp, content = client.request(self.url('authorize'), "GET",
                                       headers=headers)

        csrf = self.get_csrf(content)
        data = urllib.urlencode({'authorize_access': True,
                                 'csrfmiddlewaretoken': csrf})
        resp, content = client.request(self.url('authorize'), "POST",
                                       body=data, headers=headers)
        assert resp.status == 200, 'Status was: %s' % resp.status

        # Step 4, Now that its authorized, get the access token
        resp, content = client.request(self.url('access_token'), "GET")
        assert resp.status == 200, 'Status was: %s' % resp.status
        access_token = dict(parse_qsl(content))

        # Yay, save token.
        self.data['access_token'] = access_token
        self.save_storage()

    def get_params(self):
        return dict(oauth_consumer_key=self.data['consumer_key'],
                    oauth_nonce=oauth.generate_nonce(),
                    oauth_signature_method='HMAC-SHA1',
                    oauth_timestamp=int(time.time()),
                    oauth_version='1.0')

    def _send(self, url, method, data):
        conn = httplib.HTTPConnection("%s:%d" % (self.domain, self.port))

        req = oauth.Request(method=method, url=url,
                            parameters=self.get_params())
        req.sign_request(oauth.SignatureMethod_HMAC_SHA1(),
                         self.get_consumer(), self.get_access())

        post_data = encode_multipart(boundary, data)
        headers = req.to_header()
        headers.update({'Content-Type':
                        'multipart/form-data; boundary=%s' % boundary})
        conn.request(method, self.shorten(url), body=post_data,
                     headers=headers)
        response = conn.getresponse()
        return json.loads(response.read())

    def get_user(self):
        return self._send(self.url('user'), 'GET', {})

    def create_addon(self, data):
        # example:
        # data = {'id': 'sdefsfd', 'name':'sdfsdf', 'text':'sdfsdf',
        #         'eula':'sdfsdfsdf', 'builtin':0, 'guid': 'sdfsdfsdf',
        #         'xpi': somexpi}
        return self._send(self.url('addon'), 'POST', data)


if __name__ == '__main__':
    username = 'amckay@mozilla.com'
    amo = AMOOAuth(domain="addons.mozilla.local", port=8000, protocol='http')
    if not amo.has_access_token():
        # This is an example, don't get too excited.
        amo.set_consumer(consumer_key='CmAn9KhXR8SD3xUSrf',
                         consumer_secret='4hPsAW9yCecr4KRSR4DVKanCkgpqDETm')
        amo.authenticate(username=username)
    print amo.get_user()
