#!/usr/bin/env python3

import argparse
import os
import sys
import glob
import json
from collections import namedtuple

import tabulate  # pip install tabulate

PROG = os.path.basename(sys.argv[0])

def main():
    parser = argparse.ArgumentParser(
        description='get stats on data',
    )
    parser.add_argument('STRUCTNAME')
    parser.add_argument(
        '--sort', type=parse_sort, default='-game', help=
        "Sort order.  Valid fields are: [{}].".format(', '.join(STAT_NAMES))
        + "  You can abbreviate any field to a prefix so long as it is unambiguous."
        + "  Prefix with a + for ascending, or an optional - for descending."
    )
    parser.add_argument(
        '-F', '--format', type=parse_format, default='game,size,goodb,wipb,goodf,wipf,good%', help=
        'Row format as a comma-separated list of field names.  Valid field names are documented under --sort.'
    )
    args = parser.parse_args()

    table = get_data_table(args.STRUCTNAME, args.sort, args.format)
    print(tabulate.tabulate(table, headers=args.format, floatfmt='.2f'))

STAT_NAMES = {
    'game': None,
    'size': None,
    'goodfields': None,
    'wipfields': None,
    'goodbytes': None,
    'wipbytes': None,
    'goodpercent': 'good%',
    'wippercent': 'wip%',
    'good%': None,
    'wip%': None,
}

def get_data_table(struct_name, sort, format):
    all_data = []
    for datadir in glob.glob('data/th*'):
        game = os.path.basename(datadir)

        try:
            with open(os.path.join(datadir, 'type-structs-own.json')) as f:
                structs_json = json.load(f)
        except FileNotFoundError:
            continue
        if struct_name not in structs_json:
            continue
        struct_json = structs_json[struct_name]
        struct_json = [(int(off, 16), name, ty) for (off, name, ty) in struct_json]
        all_data.append(get_struct_stats(game, struct_json))

    sort_order, sort_field = sort
    all_data.sort(key=lambda x: x[sort_field])
    if sort_order == '-':
        all_data = all_data[::-1]

    return [
        [row[field] for field in format]
        for row in all_data
    ]

def get_struct_stats(game, struct_json):
    data = dict(
        game=game, size=struct_json[-1][0],
        goodbytes=0, goodfields=0, wipbytes=0, wipfields=0,
    )
    for (cur_offset, cur_field, cur_type), (next_offset, _ , _) in zip(struct_json, struct_json[1:]):
        if not cur_type or 'zComment' in cur_type:
            continue
        field_size = next_offset - cur_offset
        
        if not cur_field.startswith('__'):
            data['goodbytes'] += field_size
            data['goodfields'] += 1
        data['wipbytes'] += field_size
        data['wipfields'] += 1

    if data['size'] == 0:
        # the struct is clearly undocumented, so zero is an appropriate choice
        data['good%'] = 0
        data['wip%'] = 0
    else:
        data['good%'] = data['goodbytes'] / data['size'] * 100
        data['wip%'] = data['wipbytes'] / data['size'] * 100

    return data


# ------------------------------------------------------

def parse_field(s):
    possibilities = [col for col in STAT_NAMES if col.startswith(s)]
    if not possibilities:
        choices_str = ', '.join(STAT_NAMES)
        raise argparse.ArgumentError(f'no column {repr(s)}, choices are: [{choices_str}]')
    if len(possibilities) > 2:
        choices_str = ', '.join(possibilities)
        raise argparse.ArgumentError(f'ambiguous column {repr(s)}, please be more specific: {choices_str}')

    field = possibilities[0]
    while isinstance(STAT_NAMES[field], str):
        field = STAT_NAMES[field]  # resolve aliases
    return field

def parse_sort(s):
    error_msg = lambda: "sort field one of the following, optionally preceded by '+' or '-': [{}]".format(', '.join(STAT_NAMES))
    if not len(s):
        raise argparse.ArgumentError(error_msg())

    if s[0] in '-+':
        order = s[0]
        s = s[1:]
    else:
        # let - be optional, because argparse is annoying with leading '-' in option args
        # (thankfully, descending is generally a good default)
        order = '-'

    return (order, parse_field(s))

def parse_format(s):
    return [parse_field(x.strip()) for x in s.split(',')]

# ------------------------------------------------------

def warn(*args, **kw):
    print(f'{PROG}:', *args, file=sys.stderr, **kw)

def die(*args, code=1):
    warn('Fatal:', *args)
    sys.exit(code)

# ------------------------------------------------------

if __name__ == '__main__':
    main()
