#!/usr/bin/env python3

import argparse
import os
import sys
import json

PROG = os.path.basename(sys.argv[0])

def main():
    parser = argparse.ArgumentParser(
        description='get diffable form of funcs',
    )
    parser.add_argument('INPUT')
    args = parser.parse_args()
    for x in json.load(open(args.INPUT)):
        print(x['name'])

# ------------------------------------------------------

def warn(*args, **kw):
    print(f'{PROG}:', *args, file=sys.stderr, **kw)

def die(*args, code=1):
    warn('Fatal:', *args)
    sys.exit(code)

# ------------------------------------------------------

if __name__ == '__main__':
    main()
