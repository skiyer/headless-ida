
# run with `headless-ida /path/to/idat /bin/ls search_string_refs.py`
# or     `headless-ida server:18000 /bin/ls search_string_refs.py`

import idautils, ida_name, ida_funcs

for s in idautils.Strings():
    if "error" in str(s).lower():
        print(f"\nString: \"{s}\" at {hex(s.ea)}")
        for xref in idautils.DataRefsTo(s.ea):
            func = ida_funcs.get_func(xref)
            if func:
                print(f"  Referenced by: {ida_name.get_ea_name(func.start_ea)} at {hex(xref)}")
