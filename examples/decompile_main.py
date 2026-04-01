
# run with `headless-ida /path/to/idat /bin/ls decompile_main.py`
# or     `headless-ida server:18000 /bin/ls decompile_main.py`

import idautils, ida_funcs, ida_hexrays

for ea in idautils.Functions():
    name = ida_funcs.get_func_name(ea)
    if name == "main":
        cfunc = ida_hexrays.decompile(ea)
        if cfunc:
            print(str(cfunc))
        break
