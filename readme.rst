amo-oauth
=======================

This is a sample module to test the OAuth on AMO (addons.mozilla.org)
and provide as a completely stand alone example of how to interact with the
OAuth on AMO.

Because this is all scripted, we have to do quite a lot more work that a
browser would happily hide from you like grabbing cookies and CSRF tokens.

Step 1: you'll need to create a consumer on the AMO site you are testing. At
the moment this requires admin access.

Step 2: using that consumer key and secret, authenticate your self.

>>> import amo
>>> auth = amo.AMOOAuth(domain="addons.mozilla.local", port=8000, protocol='http')
>>> auth.set_consumer(consumer_key='CmAn9KhXR8SD3xUSrf', consumer_secret='xxx')

This will store the OAuth credentials in plain text in a ~/.amo-oauth file.

Step 3: you can now run repeated methods on AMO without having to authenticate
other than using your OAuth tokens.

>>> import amo
>>> auth = amo.AMOOAuth(domain="addons.mozilla.local", port=8000, protocol='http')
>>> auth.get_user()
{u'email': u'amckay@mozilla.com'}

Notes:

- This is not pretending to be a full library implementation, more a way to
  test this externally. Hence, it's fragile.

- Storing your credentials in ~/.amo-oauth isn't very secure, so don't pretend
  it is.

License: BSD
