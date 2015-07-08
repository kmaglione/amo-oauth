import argparse
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

from amo_oauth import AMOOAuth

parser = argparse.ArgumentParser()

parser.add_argument('-u', '--base-url', dest='base_url', action='store')
parser.add_argument('-K', '--api-key', dest='api_key', action='store')
parser.add_argument('-S', '--api-secret', dest='api_secret', action='store')

parser.add_argument('action', action='store',
                    choices=('user', 'addon', 'addons', 'version',
                             'versions', 'auth', 'perf',
                             'checksums'))
parser.add_argument('args', nargs='*')

args = parser.parse_args()

kw = {}
if args.base_url:
    kw['base_url'] = args.base_url

amo = AMOOAuth(**kw)
amo.set_consumer(consumer_key=args.api_key,
                 consumer_secret=args.api_secret)

if args.action == 'auth':
    amo.authenticate(username=args.args[0])

elif args.action == 'user':
    print amo.get_user()

elif args.action == 'checksums':
    if not args.args:
        print amo.get_checksums()
    else:
        assert args.args[0] == 'set'
        file = (sys.stdin if len(args.args) < 2 else
                open(args.args[1], 'r'))

        print amo.set_checksums(file.read())
