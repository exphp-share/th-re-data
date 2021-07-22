try:
    import binaryninja as bn
    from binaryninja import BinaryView
except ImportError:
    raise ImportError("These tests cannot be run standalone.  You must call exphp_export.run_tests() from inside binary ninja.")

__all__ = ['run_tests']

# NOTE: Because we're inside binaryninja we cannot use unittest or pytest.
#       We have to do everything ourselves.
def run_tests():
    defs = globals()
    for name in defs:
        if name.startswith('test_'):
            func = defs[name]
            if callable(func):
                print(func.__name__)
                func()

# ==============================================================================

def bv_from_c_defs(c_code: str) -> BinaryView:
    bv = BinaryView()
    types_to_add = bv.parse_types_from_string(c_code)
    for name, ty in types_to_add.types.items():
        bv.define_user_type(name, ty)
    return bv

def test_lookup_named_type_definition():
    from . import _lookup_named_type_definition

    bv = bv_from_c_defs('''
        typedef int32_t Typedef1;
        typedef Typedef1 Typedef2;
        typedef Typedef2 Typedef3;

        struct S { int x; }
        typedef struct S Typedef1s;
        typedef Typedef1s Typedef2s;
        typedef Typedef2s Typedef3s;
    ''')

    def expect_typedef(name):
        kind, expanded_ty = _lookup_named_type_definition(bv, name)
        assert kind == 'typedef'
        return expanded_ty

    assert str(expect_typedef('Typedef1')) == 'int32_t'
    assert str(expect_typedef('Typedef2')) == 'Typedef1'  # This one is the nasty corner case
    assert str(expect_typedef('Typedef3')) == 'Typedef2'

    assert _lookup_named_type_definition(bv, 'S') == ['struct', None]
    assert str(expect_typedef('Typedef1s')) == 'struct S'
    assert str(expect_typedef('Typedef2s')) == 'Typedef1s'
    assert str(expect_typedef('Typedef3s')) == 'Typedef2s'

def assert_dict_subset(actual, expected):
    for k in expected:
        try:
            assert actual[k] == expected[k]
        except:
            raise ValueError(repr((actual, expected)))

def test_structure_padding():
    from . import _structure_fields, GAP_MEMBER_NAME, PADDING_MEMBER_NAME, END_MEMBER_NAME

    def run_on_struct(size, data):
        bv = bn.BinaryView()
        structure = bn.Structure()
        structure.width = size
        for i, (offset, typestr) in enumerate(data):
            structure.insert(offset, bv.parse_type_string(typestr)[0], f'field_{i}')
        structure.alignment = max(member.type.alignment for member in structure.members)  # why do i have to do this manually
        return list(_structure_fields(structure))

    # gap that is padding
    members = run_on_struct(0x08, [(0x00, 'int16_t'), (0x04, 'int32_t')])
    assert_dict_subset(members[1], {'offset': 0x02, 'name': PADDING_MEMBER_NAME})
    assert_dict_subset(members[2], {'offset': 0x04, 'name': 'field_1'})

    # gap that isn't padding because of alignment that follows
    members = run_on_struct(0x0c, [(0x00, 'int16_t'), (0x04, 'int16_t'), (0x08, 'int32_t')])
    assert_dict_subset(members[1], {'offset': 0x02, 'name': GAP_MEMBER_NAME})

    # gap that isn't padding because it's too large
    members = run_on_struct(0x0c, [(0x00, 'int16_t'), (0x08, 'int32_t')])
    assert_dict_subset(members[1], {'offset': 0x02, 'name': GAP_MEMBER_NAME})
    assert_dict_subset(members[2], {'offset': 0x08, 'name': 'field_1'})

    # end padding
    members = run_on_struct(0x08, [(0x00, 'int32_t'), (0x04, 'int16_t')])
    assert_dict_subset(members[2], {'offset': 0x06, 'name': PADDING_MEMBER_NAME})
    assert_dict_subset(members[3], {'offset': 0x08, 'name': END_MEMBER_NAME})

    # no end padding
    members = run_on_struct(0x06, [(0x00, 'int16_t'), (0x04, 'int16_t')])
    assert_dict_subset(members[2], {'offset': 0x04, 'name': 'field_1'})
    assert_dict_subset(members[3], {'offset': 0x06, 'name': END_MEMBER_NAME})

def test_packed_struct():
    from . import _structure_fields, GAP_MEMBER_NAME, END_MEMBER_NAME

    def run_on_struct(size, data):
        bv = bn.BinaryView()
        structure = bn.Structure()
        structure.packed = True
        structure.width = size
        for i, (offset, typestr) in enumerate(data):
            structure.insert(offset, bv.parse_type_string(typestr)[0], f'field_{i}')
        return list(_structure_fields(structure))

    members = run_on_struct(0x0a, [(0x00, 'int16_t'), (0x04, 'int32_t'), (0x08, 'int16_t')])
    assert_dict_subset(members[0], {'offset': 0x00, 'name': 'field_0'})
    assert_dict_subset(members[1], {'offset': 0x02, 'name': GAP_MEMBER_NAME})
    assert_dict_subset(members[2], {'offset': 0x04, 'name': 'field_1'})
    assert_dict_subset(members[3], {'offset': 0x08, 'name': 'field_2'})
    assert_dict_subset(members[4], {'offset': 0x0a, 'name': END_MEMBER_NAME})

    # end gap
    members = run_on_struct(0x0a, [(0x00, 'int16_t')])
    assert_dict_subset(members[0], {'offset': 0x00, 'name': 'field_0'})
    assert_dict_subset(members[1], {'offset': 0x02, 'name': GAP_MEMBER_NAME})
    assert_dict_subset(members[2], {'offset': 0x0a, 'name': END_MEMBER_NAME})

def test_union():
    from . import _structure_fields

    bv = bv_from_c_defs('''
        union Union {
            int32_t four;
            int16_t two;
        }
    ''')
    members = list(_structure_fields(bv.types['Union'].structure))
    assert len(members) == 2
    assert_dict_subset(members[0], {'offset': 0x00, 'name': 'four'})
    assert_dict_subset(members[1], {'offset': 0x00, 'name': 'two'})
