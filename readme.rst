amo-oauth
=======================

This is a sample module to test the OAuth on AMO (addons.mozilla.org)
and provide as a completely stand alone example of how to interact with the
OAuth on AMO.

Step 1: you'll need to create a consumer on the AMO site you are testing. At
the moment this requires admin access, so ask your friendly AMO contact.

Step 2: using that consumer key and secret...

>>> from amo import AMOOAuth
>>> amo = AMOOAuth(	domain="addons-dev.allizom.org", 
				port=443, 
				protocol='https')

>>> amo.set_consumer(consumer_key='XXX',
                 consumer_secret='XXX')

>>> print amo.get_user()
{u'email': u'amckay@mozilla.com'}

Notes:

- This is not pretending to be a full library implementation, more a way to
  test this externally. Hence, it's fragile.

License: BSD
