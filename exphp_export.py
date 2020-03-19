from __future__ import print_function

# Script used to export these data files from binja.
#
# In binja's python console:
#
# >>> import exphp_export; exphp_export.run(bv)

import os
import json
from collections import defaultdict
import contextlib
from binaryninja import SymbolType, Type

def run(bv, path=r'F:\asd\clone\th16re-data'):
    do_symbols(bv, path=path)
    do_types(bv, path=path)
    
def do_symbols(bv, path):
    # precompute expensive properties
    bv_data_vars = bv.data_vars
    bv_symbols = bv.symbols

    datas = []
    funcs = []
    labels = defaultdict(list)
    for name, symbol in bv_symbols.items():
        address = symbol.address
        if symbol.type == SymbolType.DataSymbol:
            if name.startswith('data_') and is_hex(name[5:]):
                continue
            try:
                t = bv_data_vars[address].type
            except KeyError:
                continue

            if name.startswith('__import_') or name.startswith('__export_'):
                continue

            for infix in ['__case_', '__cases_']:
                if infix in name:
                    kind, rest = name.split(infix)
                    labels[kind].append((nice_hex(address), rest))
                    break
            else:
                datas.append(dict(name=name, addr=nice_hex(address), type=str(t), comment=bv.get_comment_at(address) or None))
        
        elif symbol.type == SymbolType.FunctionSymbol:
            # Identify functions that aren't worth sharing
            def is_boring(name):
                # these suffixes don't convey enough info for the name to be worth sharing if there's nothing else
                name = strip_suffix(name, '_identical_twin')
                name = strip_suffix(name, '_twin')
                name = strip_suffix(name, '_sister')
                name = strip_suffix(name, '_sibling')

                # For some things I've done nothing more than change the prefix using a script
                for prefix in ['sub', 'leaf', 'seh', 'SEH']:
                    if name.startswith(prefix + '_') and is_hex(name[len(prefix):].lstrip('_')):
                        return True
                return False
            
            if is_boring(name):
                continue

            funcs.append(dict(name=name, addr=nice_hex(address), comment=bv.get_comment_at(address) or None))
    
    datas.sort()
    funcs.sort()
    for v in labels.values():
        v.sort()

    # Python3's insertion-order dicts would make the output of json.dump "nice enough",
    # but Python2's dict order is so bad we need to step in and do something about it.
    with open_output_json_with_validation(os.path.join(path, 'statics.json')) as f:
        nice_json_array(f, 0, datas, lambda f, d: json_object_with_key_order(f, d, ['addr', 'name', 'type', 'comment']))

    with open_output_json_with_validation(os.path.join(path, 'funcs.json')) as f:
        nice_json_array(f, 0, funcs, lambda f, d: json_object_with_key_order(f, d, ['addr', 'name', 'comment']))

    with open_output_json_with_validation(os.path.join(path, 'labels.json')) as f:
        nice_json_object_of_array(f, 0, labels, lambda f, x: json.dump(x, f))

def strip_suffix(s, suffix):
    return s[:len(s)-len(suffix)] if s.endswith(suffix) else s

def nice_hex(x):
    s = hex(x)
    return s[:-1] if s.endswith('L') else s

def do_types(bv, path):
    bv_types = bv.types

    structures = {}
    typedefs = {}
    enumerations = {}
    for type_name in bv_types:
        if bv_types[type_name].structure:
            structure = bv_types[type_name].structure
            structures[str(type_name)] = structure_to_cereal(structure, bv_types[type_name])

        elif bv_types[type_name].enumeration:
            enumeration = bv_types[type_name].enumeration
            enumerations[str(type_name)] = [(m.name, m.value) for m in enumeration.members]

        else:
            typedefs[str(type_name)] = {'size': bv_types[type_name].width, 'def': str(bv_types[type_name])}

    with open_output_json_with_validation(os.path.join(path, 'type-aliases.json')) as f:
        nice_json_object(f, 0, typedefs, lambda f, d: json_object_with_key_order(f, d, ['def', 'size']))

    structures_own = {k: v for (k, v) in structures.items() if k.startswith('z')}
    structures_ext = {k: v for (k, v) in structures.items() if not k.startswith('z')}
    with open_output_json_with_validation(os.path.join(path, 'type-structs-own.json')) as f:
        nice_json_object_of_array(f, 0, structures_own, lambda f, d: json.dump(d, f))
    with open_output_json_with_validation(os.path.join(path, 'type-structs-ext.json')) as f:
        nice_json_object_of_array(f, 0, structures_ext, lambda f, d: json.dump(d, f))

    with open_output_json_with_validation(os.path.join(path, 'type-enums.json')) as f:
        nice_json_object_of_array(f, 0, enumerations, lambda f, d: json.dump(d, f))

@contextlib.contextmanager
def open_output_json_with_validation(path):
    """ Open a file for writing json.  Once the 'with' block is exited, the file will be
    reopened for reading to validate the JSON. """
    with open(path, 'w') as f:
        yield f

    json.load(open(path)) # this will fail if the JSON is invalid

def structure_to_cereal(structure, ty):
    # Include a fake field at the max offset to help simplify things
    effective_members = [(x.offset, x.name, x.type) for x in structure.members]
    effective_members.append((structure.width, None, None))

    # Don't emit large filler char fields
    is_filler = lambda name, ty: name and ty and ty.element_type and name.startswith('_') and ty.element_type.width == 1 and ty.width > 64
    effective_members = [(off, name, ty) for (off, name, ty) in effective_members if not is_filler(name, ty)]

    # Unknown area at beginning
    output = []
    if effective_members[0][0] != 0:
        output.append(('0x0', '__unknown', None))

    for (offset, name, ty), (next_offset, _, _) in window2(effective_members):
        output.append((nice_hex(offset), name, str(ty)))

        unused_bytes = next_offset - offset - ty.width
        if unused_bytes:
            output.append((nice_hex(offset + ty.width), '__unknown', None))
    output.append((nice_hex(structure.width), '__end', None))
    return output

def window2(it):
    it = iter(it)
    prev = next(it)
    for x in it:
        yield prev, x
        prev = x

def json_object_with_key_order(file, obj, keys):
    if not obj:
        print('{}', file=file)
        return
    
    first = True
    for key in keys:
        print('{' if first else ', ', end='', file=file)
        first = False

        json.dump(key, file)
        print(': ', end='', file=file)
        json.dump(obj[key], file)

    print('}', end='', file=file)

def nice_json_array(file, indent, arr, func):
    arr = list(arr)
    if not arr:
        print('[]', file=file)
        return
    
    first = True
    for x in arr:
        print(' ' * indent + ('[ ' if first else ', '), end='', file=file)
        first = False
        func(file, x)
        print(file=file)

    print(' ' * indent + ']', file=file)

def nice_json_object_of_array(file, indent, obj, func):
    if not obj:
        print('{}', file=file)
        return
    
    first = True
    for key in sorted(obj):
        print('{ ' if first else ', ', end='', file=file)
        print(json.dumps(key) + ': ', end='', file=file)
        print(file=file)
        first = False
        nice_json_array(file, indent+2, obj[key], func)
        print(file=file)
    print(' ' * indent + '}', file=file)

def nice_json_object(file, indent, obj, func):
    if not obj:
        print('{}', file=file)
        return
    
    first = True
    for key in sorted(obj):
        print(' ' * indent + ('{ ' if first else ', '), end='', file=file)
        print(json.dumps(key) + ': ', end='', file=file)
        first = False
        func(file, obj[key])
        print(file=file)
    print(' ' * indent + '}', file=file)

def is_hex(s):
    try:
        int('0x' + s, 16)
    except ValueError:
        return False
    return True
