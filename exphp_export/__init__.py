from __future__ import print_function

# Script used to export these data files from binja.
#
# In binja's python console:
#
# >>> import exphp_export; exphp_export.run(bv)

import os
import re
import json
import glob
from collections import defaultdict
import contextlib
import typing as tp
from binaryninja import (
    BinaryView, Symbol, SymbolType, Type, log, BinaryViewType, TypeClass,
    FunctionParameter, QualifiedName, TypeLibrary
)

from .test import run_tests

BNDB_DIR = r"E:\Downloaded Software\Touhou Project"
JSON_DIR = r"F:\asd\clone\th16re-data\data"
MD5SUMS_FILENAME = 'md5sums.json'
ALL_MD5_KEYS = ['bndb', 'funcs.json', 'labels.json', 'statics.json', 'types-own.json']
COMMON_DIRNAME = '_common'
GAMES = [
    "th06.v1.02h",
    "th07.v1.00b",
    "th08.v1.00d",
    "th09.v1.50a",
    "th095.v1.02a",
    "th10.v1.00a",
    "th11.v1.00a",
    "th12.v1.00b",
    "th125.v1.00a",
    "th128.v1.00a",
    "th13.v1.00c",
    "th14.v1.00b",
    "th143.v1.00a",
    "th15.v1.00b",
    "th16.v1.00a",
    "th165.v1.00a",
    "th17.v1.00b",
    "th18.v1.00a",
]
TAG_KEYWORD = 'is'

TypeTree = tp.Dict

def export(bv, path, common_types={}):
    export_symbols(bv, path=path)
    export_types(bv, path=path, common_types=common_types)

def open_bv(path, **kw):
    # Note: This is now a context manager, hurrah!
    return BinaryViewType.get_view_of_file(path, **kw)

def compute_md5(path):
    import hashlib
    return hashlib.md5(open(path,'rb').read()).hexdigest()

def dict_get_path(d, parts, default=None):
    for part in parts:
        if part not in d:
            return default
        d = d[part]
    return d

def export_all(games=GAMES, bndb_dir=BNDB_DIR, json_dir=JSON_DIR, force=False, emit_status=print):
    # we will autocreate some subdirs, but for safety against mistakes
    # we won't create anything above the output dir itself
    require_dir_exists(os.path.dirname(json_dir))

    old_md5sums = {} if force else read_md5s_file(json_dir)

    common_types = read_common_types(json_dir)

    for game in games:
        bndb_path = os.path.join(bndb_dir, f'{game}.bndb')
        json_subdir = os.path.join(json_dir, f'{game}')
        if compute_md5(bndb_path) == lookup_md5(old_md5sums, game, 'bndb'):
            emit_status(f"{game}: up to date")
            continue

        emit_status(f"{game}: exporting...")
        with open_bv(bndb_path, update_analysis=False) as bv:
            os.makedirs(json_subdir, exist_ok=True)
            export(bv, path=json_subdir, common_types=common_types)

        update_md5s(games=[game], keys=ALL_MD5_KEYS, bndb_dir=bndb_dir, json_dir=json_dir)
    emit_status("done")

def export_all_common(bv, json_dir=JSON_DIR, force=False, emit_status=print):
    """ Update the json files in the _common directory, acquiring types from the given BV. """
    require_dir_exists(os.path.dirname(json_dir))
    os.makedirs(os.path.join(json_dir, COMMON_DIRNAME), exist_ok=True)

    # We want to make sure everything actually updates, or else we could be left with inconsistencies.
    get_types_path = lambda name: os.path.join(json_dir, COMMON_DIRNAME, name, 'types-ext.json')
    invalidated_dirs = [name for name in os.listdir(json_dir) if os.path.exists(get_types_path(name))]

    things_to_update = {}
    for type_library in bv.type_libraries:
        if not type_library.named_types:
            continue  # empty, don't bother
        dirname = type_library.name.rsplit('.', 1)[0]
        things_to_update[dirname] = (export_types_from_type_library, bv, get_types_path(dirname), type_library)

    things_to_update['pe'] = (export_pe_types, bv, get_types_path('pe'))

    things_to_update[bv.platform.name] = (export_types_from_dict, bv, get_types_path(bv.platform.name), bv.platform.types, {})

    names_unable_to_update = [name for name in invalidated_dirs if name not in things_to_update]
    if names_unable_to_update:
        err_msg = f'unable to update: {names_unable_to_update}.  Perhaps this is only available in another BV?'
        log.log_error(err_msg)
        if not force:
            raise RuntimeError(err_msg)

    for key, (func, *args) in things_to_update.items():
        print(get_types_path(key))
        os.makedirs(os.path.join(json_dir, COMMON_DIRNAME, key), exist_ok=True)
        func(*args)

def export_symbols(bv, path):
    # precompute expensive properties
    bv_data_vars = bv.data_vars
    bv_symbols = bv.symbols

    datas = []
    funcs = []
    labels = defaultdict(list)
    ttree_converter = TypeToTTreeConverter(bv)
    for name, symbol in bv_symbols.items():
        if isinstance(symbol, list):
            symbol = symbol[0]
        address = symbol.address
        if symbol.type == SymbolType.DataSymbol:
            # Skip statics that I didn't rename.
            if any(
                name.startswith(prefix) and is_hex(name[len(prefix):])
                for prefix in ['data_', 'jump_table_']
            ):
                continue

            if name in [
                '__dos_header', '__dos_stub', '__rich_header', '__coff_header',
                '__pe32_optional_header', '__section_headers',
            ]:
                continue

            # There's a large number of symbols autogenerated by binja for DLL functions.
            # Since they can be autogenerated, there's no point sharing them.
            if name.startswith('__import_') or name.startswith('__export_'):
                continue

            # My naming pattern for case labels.
            for infix in ['__case_', '__cases_']:
                if infix in name:
                    kind, rest = name.split(infix)
                    labels[kind].append(dict(addr=hex(address), label=rest))
                    break
            else:
                try:
                    t = bv_data_vars[address].type
                except KeyError:
                    continue

                datas.append(dict(addr=hex(address), name=name, type=ttree_converter.to_ttree(t), comment=bv.get_comment_at(address) or None))
                if datas[-1]['comment'] is None:
                    del datas[-1]['comment']

        elif symbol.type == SymbolType.FunctionSymbol:
            # Identify functions that aren't worth sharing
            def is_boring(name):
                # Done by binja, e.g. 'j_sub_45a83#4'
                if '#' in name:
                    return True

                # these suffixes don't convey enough info for the name to be worth sharing if there's nothing else
                name = strip_suffix(name, '_identical_twin')
                name = strip_suffix(name, '_twin')
                name = strip_suffix(name, '_sister')
                name = strip_suffix(name, '_sibling')

                # For some things I've done nothing more than change the prefix using a script
                for prefix in ['sub', 'leaf', 'seh', 'SEH', 'j_sub']:
                    if name.startswith(prefix + '_') and is_hex(name[len(prefix):].lstrip('_')):
                        return True
                return False

            if is_boring(name):
                continue

            funcs.append(dict(addr=hex(address), name=name, comment=bv.get_comment_at(address) or None))
            if funcs[-1]['comment'] is None:
                del funcs[-1]['comment']

    datas.sort(key=lambda x: int(x['addr'], 16))
    funcs.sort(key=lambda x: int(x['addr'], 16))
    for v in labels.values():
        v.sort(key=lambda x: int(x['addr'], 16))

    with open_output_json_with_validation(os.path.join(path, 'statics.json')) as f:
        nice_json(f, datas, {'@type': 'block-array'})

    with open_output_json_with_validation(os.path.join(path, 'funcs.json')) as f:
        nice_json(f, funcs, {'@type': 'block-array'})

    with open_output_json_with_validation(os.path.join(path, 'labels.json')) as f:
        nice_json(f, labels, {'@type': 'block-mapping', 'element': {'@type': 'block-array'}})

def strip_suffix(s, suffix):
    return s[:len(s)-len(suffix)] if s.endswith(suffix) else s

def export_types(bv, path, common_types: tp.Dict[str, TypeTree] = {}):
    """ Writes all type-related json files for a bv to a directory. """
    our_types = {}
    ext_types = {}
    for k, v in bv.types.items():
        if str(k).startswith('z'):
            our_types[k] = v
        else:
            ext_types[k] = v
    export_types_from_dict(bv, os.path.join(path, 'types-own.json'), our_types, common_types)
    export_types_from_dict(bv, os.path.join(path, 'types-ext.json'), ext_types, common_types)

def export_types_from_type_library(bv, path, type_library: TypeLibrary):
    """ Write a single file like ``types-own.json`` containing all types from a type library. """
    # Totally ignore the input bv and create one with no other type libraries to avoid competition
    bv = BinaryView()
    bv.add_type_library(type_library)
    # trick the bv into actually loading all of the types
    for name in type_library.named_types:
        bv.parse_type_string(str(name))  # the bv will automatically load type library types while parsing

    types_to_export = {}
    for name in type_library.named_types:
        types_to_export[name] = bv.get_type_by_name(name)

    export_types_from_dict(bv, path, types_to_export, common_types={})

def export_pe_types(bv, path):
    """ Write a single file like ``types-own.json`` containing the PE header types. """
    types = {k: v for (k, v) in bv.types.items() if bv.get_type_id(k).startswith('pe:')}
    export_types_from_dict(bv, path, types, common_types={})

def export_types_from_dict(
        bv: BinaryView,
        path: str,
        types_to_export: tp.Mapping[QualifiedName, Type],
        common_types: tp.Dict[str, TypeTree] = {},
):
    """ Write a single file like ``types-own.json`` for the given types. """
    ttree_converter = TypeToTTreeConverter(bv)

    types = {}
    for (type_name, ty) in types_to_export.items():
        classification, expanded_ty = _lookup_named_type_definition(bv, type_name)
        cereal = {
            TAG_KEYWORD: classification,
            'size': hex(ty.width),
            'align': ty.alignment,
        }
        if classification == 'struct' or classification == 'union':
            cereal.update(structure_to_cereal(ty.structure, ttree_converter, _name_for_debug=type_name))
        elif classification == 'enum':
            cereal.update(enum_to_cereal(ty.enumeration))
        elif classification == 'typedef':
            cereal['type'] = ttree_converter.to_ttree(expanded_ty)

        types[str(type_name)] = cereal

    # Exclude types that already have matching definitions in common/
    for key in list(types):
        if types[key] == common_types.get(key):
            del types[key]

    with open_output_json_with_validation(path) as f:
        nice_json(f, types, {
            '@type': 'block-mapping',
            '@line-sep': 1,
            'element': {
                '@type': 'object-variant',
                '@tag': TAG_KEYWORD,
                'struct': {
                    '@type': 'block-object',
                    'members': {'@type': 'block-array'},
                },
                'enum': {
                    '@type': 'block-object',
                    'values': {'@type': 'block-array'}
                },
                'union': {
                    '@type': 'block-object',
                    'members': {'@type': 'block-array'}
                },
                'typedef': {
                    '@type': 'inline',
                },
            },
        })

def read_common_types(json_dir):
    types = {}
    for path in glob.glob(os.path.join(json_dir, '_common', '*', 'types*.json')):
        types.update(json.load(open(path)))
    return types

# =================================================


def _lookup_named_type_definition(bv, name: QualifiedName) -> tp.Tuple[str, tp.Optional[Type]]:
    """
    Look up a named type, while dealing with all of binary ninja's typedef oddities.

    This is the most proper way to look up the definition of a struct/enum/typedef!
    QualifiedNames are superior to type ids for this purpose, because there are certain kinds
    of typedefs that are impossible to recover from a type_id due to auto-expansion.

    Returns ``[kind, expansion_type]``, where ``kind`` is one of ``'struct', 'union', 'enum', 'typedef'``.
    In the case of ``'typedef'``, you should ignore the type binja returns from name and type-id lookups,
    because it is difficult to work with. ``expansion_type`` is an additional payload for ``'typedef'``
    which represents the type that the typedef expands into. (it is ``None`` for other kinds)
    """
    ty = bv.get_type_by_name(name)

    # Binja wouldn't have auto-expanded a typedef referring to a struct or enum,
    # so in these cases we can be sure that 'name' refers to the struct/enum itself.
    if ty.type_class == TypeClass.EnumerationTypeClass:
        return ('enum', None)
    elif ty.type_class == TypeClass.StructureTypeClass:
        return ('union' if ty.structure.union else 'struct', None)

    # If we make it here, it's a typedef.
    #
    # When you lookup a typedef (either by name or type_id), the following occurs:
    #
    # - If the expansion of the typedef is itself a named type (struct, enum, typedef),
    #   binja returns a NamedTypeReference representing the typedef itself. (not the target!)
    # - Otherwise, binja returns a type representing the expansion (and you lose
    #   all context related to the typedef)
    if (
        ty.type_class == TypeClass.NamedTypeReferenceClass
        and ty.registered_name
        and ty.registered_name.name == name
    ):
        # This is the typedef itself.  We want the expansion!
        #
        # Thankfully, we know that the resulting type is named, so we can call
        # 'Type.named_type_from_registered_type' which is one of the very few methods capable
        # of producing an unexpanded typedef that points to an unnamed type.
        # (dodging a nasty corner case when dealing with a typedef to a typedef to an unnamed type)
        expn_type_name = ty.named_type_reference.name
        return ('typedef', Type.named_type_from_registered_type(bv, expn_type_name))
    else:
        # This is the expansion.
        return ('typedef', ty)

def _lookup_type_id(bv, type_id):
    """
    Look up a type by type id.  This will always produce a NamedTypeReference for typedefs,
    even when the normal lookup mechanism wouldn't.
    """
    name = bv.get_type_name_by_id(type_id)
    if name:
        ty = bv.get_type_by_name(name)
        # See comments in _lookup_named_type_definition
        if ty.type_class not in [
            TypeClass.StructureTypeClass,    # a struct/union (and not a typedef to one)
            TypeClass.EnumerationTypeClass,  # a enum (and not a typedef to one)
        ]:
            # We enter this branch IFF it is a typedef.
            # 'ty' is unreliable but the following is guaranteed to work
            return Type.named_type_from_registered_type(bv, name)

    # Not a typedef, so we can trust the normal lookup.
    return bv.get_type_by_id(type_id)

def import_all_functions(games=GAMES, bndb_dir=BNDB_DIR, json_dir=JSON_DIR, emit_status=print):
    return _import_all_symbols(
        games=games, bndb_dir=bndb_dir, json_dir=json_dir, emit_status=print,
        json_filename='funcs.json', symbol_type=SymbolType.FunctionSymbol,
    )

def import_all_statics(games=GAMES, bndb_dir=BNDB_DIR, json_dir=JSON_DIR, emit_status=print):
    return _import_all_symbols(
        games=games, bndb_dir=bndb_dir, json_dir=json_dir, emit_status=print,
        json_filename='statics.json', symbol_type=SymbolType.DataSymbol,
    )

# =================================================

def _import_all_symbols(games, bndb_dir, json_dir, json_filename, symbol_type, emit_status):
    old_md5sums = read_md5s_file(json_dir)

    for game in games:
        bndb_path = os.path.join(bndb_dir, f'{game}.bndb')
        json_path = os.path.join(json_dir, f'{game}', json_filename)
        try:
            with open(json_path) as f:
                funcs_json = json.load(f)
        except (IOError, json.decoder.JSONDecodeError) as e:
            emit_status(f'{game}: {e}')
            continue

        if compute_md5(json_path) == lookup_md5(old_md5sums, game, json_filename):
            emit_status(f"{game}: up to date")
            continue

        emit_status(f"{game}: checking...")
        with open_bv(bndb_path, update_analysis=False) as bv:
            if _import_symbols_from_json(bv, funcs_json, symbol_type, emit_status=lambda s: emit_status(f'{game}: {s}')):
                emit_status(f'{game}: saving...')
                bv.save_auto_snapshot()

        update_md5s(games=[game], keys=['bndb', json_filename], bndb_dir=bndb_dir, json_dir=json_dir)
    emit_status("done")

def import_funcs_from_json(bv, funcs, emit_status=None):
    return _import_symbols_from_json(bv, funcs, SymbolType.FunctionSymbol, emit_status=emit_status)
def import_statics_from_json(bv, statics, emit_status=None):
    return _import_symbols_from_json(bv, statics, SymbolType.DataSymbol, emit_status=emit_status)

def _import_symbols_from_json(bv, symbols, symbol_type, emit_status=None):
    changed = False
    for d in symbols:
        addr = int(d['addr'], 16)
        name = d['name']
        existing = bv.get_symbol_at(addr)
        if existing is not None:
            if name == existing.name:
                continue
            else:
                bv.define_user_symbol(Symbol(symbol_type, addr, name))
                changed = True
                if emit_status:
                    emit_status(f'rename {existing.name} => {name}')
        else:
            bv.define_user_symbol(Symbol(symbol_type, addr, name))
            changed = True
            if emit_status:
                emit_status(f'name {existing.name}')
    return changed

def merge_function_files(games=GAMES, json_dir=JSON_DIR, emit_status=print):
    return _merge_symbol_files(games, json_dir, 'funcs.json', emit_status)
def merge_static_files(games=GAMES, json_dir=JSON_DIR, emit_status=print):
    return _merge_symbol_files(games, json_dir, 'statics.json', emit_status)

def _merge_symbol_files(games, json_dir, filename, emit_status):
    require_dir_exists(json_dir)
    os.makedirs(os.path.join(json_dir, 'composite'), exist_ok=True)

    composite_path = os.path.join(json_dir, 'composite', filename)
    composite_items = []
    for game in games:
        with open(os.path.join(json_dir, f'{game}/{filename}')) as f:
            game_items = json.load(f)
        composite_items.extend(dict(game=game, **d) for d in game_items)

    composite_items.sort(key=lambda d: d['name'])

    with open(composite_path, 'w') as f:
        nice_json(f, composite_items, {'@type': 'block-array'})

def split_function_files(games=GAMES, json_dir=JSON_DIR, emit_status=print):
    return _split_symbol_files(games, json_dir, 'funcs.json', emit_status)
def split_static_files(games=GAMES, json_dir=JSON_DIR, emit_status=print):
    return _split_symbol_files(games, json_dir, 'statics.json', emit_status)

def _split_symbol_files(games, json_dir, filename, emit_status):
    require_dir_exists(json_dir)

    with open(os.path.join(json_dir, 'composite', filename)) as f:
        composite_items = json.load(f)
    for game in games:
        game_items = [dict(d) for d in composite_items if d['game'] == game]
        for d in game_items:
            del d['game']
        game_items.sort(key=lambda d: d['addr'])
        with open(os.path.join(json_dir, f'{game}/{filename}'), 'w') as f:
            nice_json(f, game_items, {'@type': 'block-array'})

def enum_to_cereal(enumeration):
    return {'values': [{'name': m.name, 'value': m.value} for m in enumeration.members]}

def structure_to_cereal(structure, ttree_converter, _name_for_debug=None):
    # I use a plugin to fill extremely large gaps with char arrays to make the UI navigable.
    # These should be counted as gaps.
    ignore = lambda name, ty: name and ty and ty.element_type and name.startswith('_') and ty.element_type.width == 1 and ty.width > 64

    fields_iter = _structure_fields(structure, ignore=ignore, _name_for_debug=_name_for_debug)
    output_members = []
    for d in fields_iter:
        ty_json = None if d['type'] is None else ttree_converter.to_ttree(d['type'])

        out_row = {} if structure.union else {'offset': hex(d['offset'])}
        out_row.update({'name': d['name'], 'type': ty_json})
        output_members.append(out_row)

    out = {}
    if structure.packed:
        out['packed'] = True
    out['members'] = output_members
    return out

GAP_MEMBER_NAME = '__unknown'
PADDING_MEMBER_NAME = '__padding'
END_MEMBER_NAME = '__end'

def _structure_fields(
        structure,
        ignore=lambda name, ty: False,  # field-ignoring predicate
        _name_for_debug=None,  # struct name, used only for diagnostic purposes
):
    # Include a fake field at the max offset to help simplify things
    effective_members = [(x.offset, x.name, x.type) for x in structure.members]
    effective_members.append((structure.width, None, None))

    effective_members = [(off, name, ty) for (off, name, ty) in effective_members if not ignore(name, ty)]

    if not structure.packed and structure.width % structure.alignment != 0:
        # binary ninja allows width to not be a multiple of align, which makes arrays UB
        log.log_error(f'unpacked structure {_name_for_debug or ""} has width {structure.width} but align {structure.alignment}')

    # I use a plugin to fill extremely large gaps with char arrays to make the UI navigable.
    # These should be counted as gaps.
    is_filler = lambda name, ty: name and ty and ty.element_type and name.startswith('_') and ty.element_type.width == 1 and ty.width > 64
    effective_members = [(off, name, ty) for (off, name, ty) in effective_members if not is_filler(name, ty)]

    for (offset, name, ty), (next_offset, _, next_ty) in window2(effective_members):
        yield {'offset': offset, 'name': name, 'type': ty}
        if structure.union:
            continue # no gaps for unions

        # A gap may follow, but in a non-packed struct it may be identifiable as padding
        gap_start = offset + ty.width
        gap_name = GAP_MEMBER_NAME
        if not structure.packed:
            # note: next_ty is None at end of struct, which has alignment of the entire structure so that arrays can work
            alignment = next_ty.alignment if next_ty else structure.alignment
            padding_end = gap_start + (0 if gap_start % alignment == 0 else alignment - (gap_start % alignment))
            if next_offset == padding_end:
                gap_name = PADDING_MEMBER_NAME

        if next_offset != gap_start:
            yield {'offset': offset + ty.width, 'name': gap_name, 'type': None}

    if not structure.union:
        yield {'offset': structure.width, 'name': END_MEMBER_NAME, 'type': None}

def nice_json(file, value, schema, indent=0):
    if schema is None:
        schema = {'@type': 'inline'}

    if schema['@type'] == 'inline':
        json.dump(value, file)

    elif schema['@type'] == 'block-array':
        # Homogenous list
        assert isinstance(value, (list, tuple))
        def do_item(item):
            nice_json(file, item, schema.get('element', None), indent + 2)
        _nice_json_block(file, '[', ']', indent, schema.get('@line-sep', 0), list(value), do_item)

    elif schema['@type'] == 'block-object':
        # Heterogenous dict
        assert isinstance(value, dict)
        def do_key(key):
            print(json.dumps(key) + ': ', end='', file=file)
            nice_json(file, value[key], schema.get(key, None), indent + 2)
        _nice_json_block(file, '{', '}', indent, schema.get('@line-sep', 0), list(value), do_key)

    elif schema['@type'] == 'block-mapping':
        # Homogenous dict
        assert isinstance(value, dict)
        def do_key(key):
            print(json.dumps(key) + ': ', end='', file=file)
            nice_json(file, value[key], schema.get('element', None), indent + 2)
        _nice_json_block(file, '{', '}', indent, schema.get('@line-sep', 0), list(value), do_key)

    elif schema['@type'] == 'object-variant':
        assert isinstance(value, dict)
        tag = schema['@tag']
        variant_name = value[tag]
        sub_schema = schema.get(variant_name)
        if not sub_schema:
            sub_schema = schema['@default']
        nice_json(file, value, schema[variant_name], indent)

    else:
        assert False, schema

def _nice_json_block(file, open: str, close: str, indent: int, line_sep: int, items: tp.List, do_item: tp.Callable):
    if not items:
        print(' ' * indent + f'{open}{close}', end='', file=file)
        return
    first = True
    for item in items:
        print(file=file)
        print(' ' * indent + (f'{open} ' if first else ', '), end='', file=file)
        first = False
        do_item(item)
        print('\n' * line_sep, end='', file=file)
    print('\n' + ' ' * indent + close, end='', file=file)

#============================================================================

def read_md5s_file(json_dir=JSON_DIR):
    md5sum_path = os.path.join(json_dir, MD5SUMS_FILENAME)
    try:
        with open(md5sum_path) as f:
            return json.load(f)
    except IOError: return {}
    except json.decoder.JSONDecodeError: return {}

def update_md5s(games, keys, bndb_dir, json_dir):
    md5s = read_md5s_file(json_dir)

    path_funcs = {
        'bndb': (lambda game: os.path.join(bndb_dir, f'{game}.bndb')),
        'funcs.json': (lambda game: os.path.join(json_dir, game, 'funcs.json')),
        'labels.json': (lambda game: os.path.join(json_dir, game, 'labels.json')),
        'statics.json': (lambda game: os.path.join(json_dir, game, 'statics.json')),
        'types-own.json': (lambda game: os.path.join(json_dir, game, 'types-own.json')),
    }
    assert set(path_funcs) == set(ALL_MD5_KEYS)
    for game in games:
        if game not in md5s:
            md5s[game] = {}
        for key in keys:
            md5s[game][key] = compute_md5(path_funcs[key](game))

    with open(os.path.join(json_dir, MD5SUMS_FILENAME), 'w') as f:
        nice_json(f, md5s, {'@type': 'block-mapping'})

def lookup_md5(md5s_dict, game, key):
    assert key in ALL_MD5_KEYS # protection against typos
    print(game, key)
    return md5s_dict.get(game, {}).get(key, None)

@contextlib.contextmanager
def open_output_json_with_validation(path):
    """ Open a file for writing json.  Once the 'with' block is exited, the file will be
    reopened for reading to validate the JSON. """
    with open(path, 'w') as f:
        yield f

    with open(path) as f:
        json.load(f) # this will fail if the JSON is invalid

#============================================================================

TTREE_VALID_ABBREV_REGEX = re.compile(r'^[_\$#:a-zA-Z][_\$#:a-zA-Z0-9]*$')

class TypeToTTreeConverter:
    def __init__(self, bv):
        self.bv = bv

    def to_ttree(self, ty):
        return self._to_ttree_flat(ty)

    def _to_ttree_flat(self, ty):
        ttree = self._to_ttree_nested(ty)
        ttree = _possibly_flatten_nested_ttree(ttree)
        ttree = _further_abbreviate_flattened_ttree(ttree)
        return ttree

    # Produces a typetree where the outermost node is not a list.
    #
    # Recursive calls should use '_to_ttree_flat' if and only if they are a place that
    # cannot be chained through.  (e.g. an object field not called 'inner').
    # Otherwise they should use '_to_ttree_nested'.
    def _to_ttree_nested(self, ty):
        if ty.type_class == TypeClass.ArrayTypeClass:
            return {TAG_KEYWORD: 'array', 'len': ty.count, 'inner': self._to_ttree_nested(ty.element_type)}

        elif ty.type_class == TypeClass.PointerTypeClass:
            # FIXME this check should probably resolve NamedTypeReferences in the target,
            # in case there are typedefs to bare (non-ptr) function types.
            if ty.target.type_class == TypeClass.FunctionTypeClass:
                return self._function_ptr_type_to_ttree(ty.target)

            d = {TAG_KEYWORD: 'ptr', 'inner': self._to_ttree_nested(ty.target)}
            if ty.const:
                d['const'] = True
            return d

        elif ty.type_class == TypeClass.NamedTypeReferenceClass:
            if ty.registered_name is not None:
                # A raw typedef, instead of a reference to one.
                # Typically to get this, you'd have to call `bv.get_type_by_name` on a typedef name.
                #
                # It's not clear when type_to_ttree would ever be called with one.
                return {TAG_KEYWORD: 'named', 'name': str(ty.registered_name.name)}
            # could be a 'struct Ident' field, or a regular typedef
            return {TAG_KEYWORD: 'named', 'name': str(ty.named_type_reference.name)}

        elif ty.type_class in [TypeClass.StructureTypeClass, TypeClass.EnumerationTypeClass]:
            if ty.registered_name is not None:
                # A raw struct, enum, or union declaration, instead of a reference to one.
                #
                # It's not clear when type_to_ttree would ever be called with this.
                return {TAG_KEYWORD: 'named', 'name': str(ty.registered_name.name)}

            # an anonymous struct/union/enum
            output = {
                TAG_KEYWORD: None,  # to be filled
                'size': hex(ty.width),
                'align': ty.alignment,
            }
            if ty.type_class == TypeClass.EnumerationTypeClass:
                output[TAG_KEYWORD] = 'enum'
                output.update(enum_to_cereal(ty.enumeration))
            else:
                assert ty.type_class == TypeClass.StructureTypeClass
                output[TAG_KEYWORD] = 'union' if ty.structure.union else 'struct'
                output.update(structure_to_cereal(ty.structure, self))
            assert output[TAG_KEYWORD] is not None
            return output

        elif ty.type_class == TypeClass.VoidTypeClass:
            return {TAG_KEYWORD: 'void'}
        elif ty.type_class == TypeClass.IntegerTypeClass:
            return {TAG_KEYWORD: 'int', 'signed': bool(ty.signed), 'size': ty.width}
        elif ty.type_class == TypeClass.FloatTypeClass:
            return {TAG_KEYWORD: 'float', 'size': ty.width}
        elif ty.type_class == TypeClass.BoolTypeClass:
            return {TAG_KEYWORD: 'int', 'signed': False, 'size': ty.width}
        elif ty.type_class == TypeClass.WideCharTypeClass:
            return {TAG_KEYWORD: 'int', 'signed': False, 'size': ty.width}

        elif ty.type_class == TypeClass.FunctionTypeClass:
            raise RuntimeError(f"bare FunctionTypeClass not supported (only function pointers): {ty}")
        elif ty.type_class == TypeClass.ValueTypeClass:
            # not sure where you get one of these
            raise RuntimeError(f"ValueTypeClass not supported: {ty}")
        elif ty.type_class == TypeClass.VarArgsTypeClass:
            # I don't know how you get this;  va_list is just an alias for char*,
            # and variadic functions merely set .has_variable_arguments = True.
            raise RuntimeError(f"VarArgsTypeClass not supported: {ty}")
        else:
            raise RuntimeError(f"Unsupported type {ty}")

    def _function_ptr_type_to_ttree(self, func_ty):
        parameters = list(func_ty.parameters)
        abi = func_ty.calling_convention and str(func_ty.calling_convention)

        if (abi == 'stdcall'
            and parameters
            and parameters[0].location
            and parameters[0].location.name == 'ecx'
            and not any(p.location for p in parameters[1:])
        ):
            abi = 'fastcall'
            parameters[0] = FunctionParameter(parameters[0].type, parameters[0].name)  # remove location

        def convert_parameter(p):
            out = {'type': self._to_ttree_flat(p.type)}
            if p.name:
                out['name'] = p.name
            return out

        out = {TAG_KEYWORD: 'fn-ptr'}

        if abi:
            out['abi'] = abi

        out['ret'] = self._to_ttree_flat(func_ty.return_value)

        if parameters:
            out['params'] = list(map(convert_parameter, parameters))

        return out

# Turn a nested object ttree into a list. (destructively)
def _possibly_flatten_nested_ttree(ttree):
    return ttree  # don't implement flattening for now
# def _possibly_flatten_nested_ttree(ttree):
#     if isinstance(ttree, dict) and 'inner' in ttree:
#         flattened = []
#         while isinstance(ttree, dict) and 'inner' in ttree:
#             flattened.append(ttree)
#             ttree = ttree.pop('inner')
#         flattened.append(ttree)
#         return flattened
#     return ttree

# assert (
#     _possibly_flatten_nested_ttree({'a': 1, 'inner': {'b': 2, 'inner': {'c': 3}}})
#     == [{'a': 1}, {'b': 2}, {'c': 3}]
# )

def _further_abbreviate_flattened_ttree(ttree):
    return ttree  # don't implement abbreviations for now
# def _further_abbreviate_flattened_ttree(ttree):
#     if isinstance(ttree, list):
#         out = []
#         for x in ttree:
#             if x == {'type': 'ptr'}:
#                 out.append('*')
#             elif isinstance(x, dict) and len(x) == 2 and x['type'] == 'array':
#                 out.append(x['len'])
#             else:
#                 out.append(x)
#         return out
#     return ttree

# Turn a list ttree into a nested object. (destructively)
def _possibly_nest_flattened_ttree(ttree):
    return ttree
# def _possibly_nest_flattened_ttree(ttree):
#     if isinstance(ttree, list):
#         out = ttree.pop()
#         while ttree:
#             new_out = ttree.pop()
#             assert isinstance(new_out, dict) and 'inner' not in new_out
#             new_out['inner'] = out
#             out = new_out
#         return out
#     return ttree

#============================================================================

def window2(it):
    it = iter(it)
    prev = next(it)
    for x in it:
        yield prev, x
        prev = x

def with_key_order(d, keys):
    """ Set order of keys in a dict. (Python 3.7+ only) """
    return { k:d[k] for k in keys }

def require_dir_exists(path):
    if not os.path.exists(path):
        raise IOError(f"{path}: No such directory")

def is_hex(s):
    try:
        int('0x' + s, 16)
    except ValueError:
        return False
    return True
