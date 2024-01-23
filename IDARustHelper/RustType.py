from idaapi import *


# can add more rust types here
STR = '''
struct str {
    char* ptr;
    size_t len;
}
'''

type_list = [(STR, 'str')]

def set_rust_type():
    print("[*] Adding Rust types to IDA...")
    til = get_idati()
    for t, n in type_list:
        idc_parse_types(t, 0)
        import_type(til, -1, n)

    print(f"[*] {len(type_list)} Rust types added to IDA!")